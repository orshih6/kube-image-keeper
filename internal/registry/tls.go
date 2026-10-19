package registry

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
)

// TLSSettings are the TLS settings of the requests to registries, per host.
type TLSSettings struct {
	// Default applies to every host without an entry, and adds its CAs to
	// those of an entry.
	Default TLSEntry
	// Items are keyed by host[:port], as the registry part of an image reference.
	Items map[string]TLSEntry

	// dialContext replaces the dialer of the transports, for tests only.
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// TLSEntry are the TLS settings of one host.
type TLSEntry struct {
	// Insecure skips the verification of the certificate and allows plain HTTP.
	Insecure bool
	// CAs are added to the system trust store.
	CAs []CABundle
}

// CABundle is a PEM bundle of CA certificates, or the error met reading it.
type CABundle struct {
	// Source names where the bundle comes from, for error messages.
	Source string
	PEM    []byte
	Err    error
}

// WithTLS sets the TLS settings of the client. Nil verifies every host
// against the system trust store.
func (c *Client) WithTLS(settings *TLSSettings) *Client {
	c.tls = settings
	return c
}

// dockerHubKey is the key that applies to Docker Hub: an image of docker.io is
// requested from index.docker.io.
const dockerHubKey = "docker.io"

// entryFor returns the entry of a host, as the registry part of a reference or
// the host of a request.
// A host without an entry gets the zero entry: the default alone.
func (s *TLSSettings) entryFor(host string) TLSEntry {
	if s == nil {
		return TLSEntry{}
	}
	host = strings.ToLower(host)
	if entry, ok := s.Items[host]; ok {
		return entry
	}
	if host == name.DefaultRegistry {
		return s.Items[dockerHubKey]
	}
	return TLSEntry{}
}

// insecure reports whether a host may skip verification and use plain HTTP.
func (s *TLSSettings) insecure(host string) bool {
	return s.entryFor(host).Insecure
}

// tlsRouter sends each request through the transport of its own host, so that a
// redirect (blob storage, CDN) or a token server gets the entry of the host it
// goes to, not the one of the registry.
type tlsRouter struct {
	settings *TLSSettings

	mu         sync.Mutex
	transports map[string]http.RoundTripper
	errs       map[string]error
}

func newTLSRouter(settings *TLSSettings) *tlsRouter {
	if settings == nil {
		settings = &TLSSettings{}
	}
	return &tlsRouter{
		settings:   settings,
		transports: map[string]http.RoundTripper{},
		errs:       map[string]error{},
	}
}

func (r *tlsRouter) RoundTrip(req *http.Request) (*http.Response, error) {
	transport, err := r.transportFor(req.URL.Host)
	if err == nil && req.URL.Scheme == "http" && len(r.settings.entryFor(req.URL.Host).CAs) > 0 {
		// go-containerregistry falls back to plain HTTP on loopback and private
		// addresses; a host whose entry trusts a CA speaks TLS, so never send
		// it a request (nor credentials) in clear
		err = fmt.Errorf("plain HTTP refused for %s: its tls entry trusts a CA", strings.ToLower(req.URL.Host))
	}
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	return transport.RoundTrip(req)
}

func (r *tlsRouter) transportFor(host string) (http.RoundTripper, error) {
	host = strings.ToLower(host)

	r.mu.Lock()
	defer r.mu.Unlock()

	if transport, ok := r.transports[host]; ok {
		return transport, nil
	}
	if err, ok := r.errs[host]; ok {
		return nil, err
	}

	transport, err := r.newTransport(host)
	if err != nil {
		err = fmt.Errorf("unusable TLS settings for %s: %w", host, err)
		r.errs[host] = err
		return nil, err
	}
	r.transports[host] = transport
	return transport, nil
}

func (r *tlsRouter) newTransport(host string) (http.RoundTripper, error) {
	entry := r.settings.entryFor(host)

	key := "system"
	var bundles []CABundle
	if entry.Insecure {
		// an insecure host verifies nothing, whatever the default holds
		key = "insecure"
	} else if bundles = append(append([]CABundle{}, r.settings.Default.CAs...), entry.CAs...); len(bundles) > 0 {
		hash := sha256.New()
		for _, bundle := range bundles {
			if bundle.Err != nil {
				return nil, fmt.Errorf("CA %s: %w", bundle.Source, bundle.Err)
			}
			_ = binary.Write(hash, binary.BigEndian, uint64(len(bundle.PEM)))
			hash.Write(bundle.PEM)
		}
		key = "ca:" + hex.EncodeToString(hash.Sum(nil))
	}

	build := func() (*http.Transport, error) {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		switch {
		case entry.Insecure:
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // insecure is the user's explicit choice for this host
		case len(bundles) > 0:
			pool, err := certPool(bundles)
			if err != nil {
				return nil, err
			}
			transport.TLSClientConfig = &tls.Config{RootCAs: pool}
		}
		return transport, nil
	}

	if r.settings.dialContext != nil {
		// the test dialer is not part of the key: never share its transports
		transport, err := build()
		if err != nil {
			return nil, err
		}
		transport.DialContext = r.settings.dialContext
		return transport, nil
	}

	return sharedTransports.get(host, key, build)
}

// sharedTransports holds the transport of each request host across clients,
// so that the clients built for each check reuse the connections. A transport
// is kept with the key of what it depends on (insecure, or the CA bundles): a
// new key for the host, a rotated CA, replaces it and closes its idle
// connections.
var sharedTransports = &transportCache{hosts: map[string]hostTransport{}}

type transportCache struct {
	mu    sync.Mutex
	hosts map[string]hostTransport
}

type hostTransport struct {
	key       string
	transport *http.Transport
}

func (c *transportCache) get(host, key string, build func() (*http.Transport, error)) (*http.Transport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	previous, ok := c.hosts[host]
	if ok && previous.key == key {
		return previous.transport, nil
	}
	transport, err := build()
	if err != nil {
		return nil, err
	}
	c.hosts[host] = hostTransport{key: key, transport: transport}
	if ok {
		previous.transport.CloseIdleConnections()
	}
	return transport, nil
}

// certPool adds the bundles to the system trust store. An unusable bundle fails
// the whole pool: never fall back to a weaker verification.
func certPool(bundles []CABundle) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("could not load the system trust store: %w", err)
	}
	for _, bundle := range bundles {
		if bundle.Err != nil {
			return nil, fmt.Errorf("CA %s: %w", bundle.Source, bundle.Err)
		}
		if !pool.AppendCertsFromPEM(bundle.PEM) {
			return nil, fmt.Errorf("CA %s: %w", bundle.Source, errNoPEMCertificate)
		}
	}
	return pool, nil
}

var errNoPEMCertificate = errors.New("no valid PEM certificate")
