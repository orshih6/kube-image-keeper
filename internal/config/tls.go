package config

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/distribution/reference"
)

// DefaultCASecretKey is the key of a CA Secret read when caSecretRef sets none.
const DefaultCASecretKey = "ca.crt"

// setDefaults fills the defaults the koanf struct defaults cannot reach, as
// they do not apply to the entries of a map.
func (t *TLS) setDefaults() {
	t.Default.setDefaults()
	for host, entry := range t.Items {
		entry.setDefaults()
		t.Items[host] = entry
	}
}

func (e *TLSEntry) setDefaults() {
	if e.CASecretRef != nil && e.CASecretRef.Key == "" {
		e.CASecretRef.Key = DefaultCASecretKey
	}
}

func (t *TLS) validate() error {
	errs := make([]error, 0, 2+3*len(t.Items))

	if t.Default.Insecure {
		errs = append(errs, errors.New("tls.default: insecure is not allowed in default, set it on the host entry"))
	}
	errs = append(errs, t.Default.CASecretRef.validate("tls.default"))

	for _, host := range slices.Sorted(maps.Keys(t.Items)) {
		entry := t.Items[host]
		path := fmt.Sprintf("tls.items[%s]", host)
		if err := validateTLSHost(host); err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid host key: %w", path, err))
		}
		if entry.CASecretRef != nil && entry.Insecure {
			errs = append(errs, fmt.Errorf("%s: caSecretRef and insecure are exclusive", path))
		}
		errs = append(errs, entry.CASecretRef.validate(path))
	}

	return errors.Join(errs...)
}

func (r *CASecretRef) validate(path string) error {
	if r == nil {
		return nil
	}
	var errs []error
	if r.Namespace == "" {
		errs = append(errs, fmt.Errorf("%s.caSecretRef.namespace: must not be empty", path))
	}
	if r.Name == "" {
		errs = append(errs, fmt.Errorf("%s.caSecretRef.name: must not be empty", path))
	}
	return errors.Join(errs...)
}

// validateTLSHost checks that a key is a lowercase host[:port], with no scheme
// and no path: the registry part of an image reference, as its grammar parses it.
func validateTLSHost(host string) error {
	if host == "" {
		return errors.New("must not be empty")
	}
	if host != strings.ToLower(host) {
		return errors.New("must be lowercase")
	}
	named, err := reference.ParseNormalizedNamed(host + "/x")
	if err != nil {
		return errors.New("must be host[:port], with no scheme and no path")
	}
	if domain := reference.Domain(named); domain != host {
		return fmt.Errorf("is not a registry host: an image reference reads it as %s", domain)
	}
	if port := portOf(host); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("port %q is out of range", port)
		}
	}
	return nil
}

// portOf returns the port of a host[:port], bracketed IPv6 addresses included.
func portOf(host string) string {
	i := strings.LastIndex(host, ":")
	if i < 0 || strings.Contains(host[i:], "]") {
		return ""
	}
	return host[i+1:]
}
