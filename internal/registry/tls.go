package registry

import (
	"context"
	"net"
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

// WithTLS sets the TLS settings of the client. Stub: only the test dialer is used.
func (c *Client) WithTLS(settings *TLSSettings) *Client {
	c.tls = settings
	return c
}
