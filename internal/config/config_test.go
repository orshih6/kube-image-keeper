package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Config)
		wantError string
		// alsoWantError is a second part the error must contain, when it joins
		// several errors
		alsoWantError string
	}{
		{
			name:   "default config is valid",
			mutate: func(c *Config) {},
		},
		{
			name: "multiple valid platforms",
			mutate: func(c *Config) {
				c.Mirroring.Platforms = []Platform{
					{OS: "linux", Architecture: "amd64"},
					{OS: "linux", Architecture: "arm64", Variant: "v8"},
				}
			},
		},
		{
			name: "empty platforms list is rejected",
			mutate: func(c *Config) {
				c.Mirroring.Platforms = nil
			},
			wantError: "Platforms",
		},
		{
			name: "platform with empty architecture is rejected",
			mutate: func(c *Config) {
				c.Mirroring.Platforms = []Platform{
					{OS: "linux"},
				}
			},
			wantError: "Architecture",
		},
		{
			name: "second platform with empty architecture is rejected",
			mutate: func(c *Config) {
				c.Mirroring.Platforms = []Platform{
					{Architecture: "amd64"},
					{OS: "linux", Variant: "v8"},
				}
			},
			wantError: "Architecture",
		},
		{
			name: "tls with a default CA and per-host entries is valid",
			mutate: func(c *Config) {
				c.TLS = TLS{
					Default: TLSEntry{CASecretRef: caRef("kuik-system", "corporate-ca")},
					Items: map[string]TLSEntry{
						"harbor.corp.tld":       {CASecretRef: caRef("kuik-system", "harbor-ca")},
						"registry.lab.tld:5000": {Insecure: true},
					},
				}
			},
		},
		{
			name: "tls host key with a port is valid",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"10.0.0.1:5000": {Insecure: true}}
			},
		},
		{
			name: "tls host entry with neither caSecretRef nor insecure is valid",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"harbor.corp.tld": {}}
			},
		},
		{
			name: "tls default with insecure is rejected",
			mutate: func(c *Config) {
				c.TLS.Default = TLSEntry{Insecure: true}
			},
			wantError: "tls.default",
		},
		{
			name: "tls host entry with both caSecretRef and insecure is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{
					"harbor.corp.tld": {CASecretRef: caRef("kuik-system", "harbor-ca"), Insecure: true},
				}
			},
			wantError: "tls.items[harbor.corp.tld]",
		},
		{
			name: "tls default caSecretRef with an empty name is rejected",
			mutate: func(c *Config) {
				c.TLS.Default = TLSEntry{CASecretRef: caRef("kuik-system", "")}
			},
			wantError: "tls.default.caSecretRef.name",
		},
		{
			name: "tls default caSecretRef with an empty namespace is rejected",
			mutate: func(c *Config) {
				c.TLS.Default = TLSEntry{CASecretRef: caRef("", "corporate-ca")}
			},
			wantError: "tls.default.caSecretRef.namespace",
		},
		{
			name: "tls host caSecretRef with an empty name is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"harbor.corp.tld": {CASecretRef: caRef("kuik-system", "")}}
			},
			wantError: "tls.items[harbor.corp.tld].caSecretRef.name",
		},
		{
			name: "tls host caSecretRef with an empty namespace is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"harbor.corp.tld": {CASecretRef: caRef("", "harbor-ca")}}
			},
			wantError: "tls.items[harbor.corp.tld].caSecretRef.namespace",
		},
		{
			name: "tls host key with a scheme is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"https://harbor.corp.tld": {Insecure: true}}
			},
			wantError: "tls.items[https://harbor.corp.tld]",
		},
		{
			name: "tls host key with a path is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"harbor.corp.tld/library": {Insecure: true}}
			},
			wantError: "tls.items[harbor.corp.tld/library]",
		},
		{
			name: "tls host key with uppercase letters is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"Harbor.corp.tld": {Insecure: true}}
			},
			wantError: "tls.items[Harbor.corp.tld]",
		},
		{
			name: "tls host key with a non-numeric port is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"harbor.corp.tld:https": {Insecure: true}}
			},
			wantError: "tls.items[harbor.corp.tld:https]",
		},
		{
			name: "tls empty host key is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"": {Insecure: true}}
			},
			wantError: "tls.items[]",
		},
		{
			name: "tls host key with two ports is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"harbor.corp.tld:5000:6000": {Insecure: true}}
			},
			wantError: "tls.items[harbor.corp.tld:5000:6000]",
		},
		{
			name: "tls host key with an unbracketed IPv6 address is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"fe80::1": {Insecure: true}}
			},
			wantError: "tls.items[fe80::1]",
		},
		{
			name: "tls host key with an underscore is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"harbor_corp.tld": {Insecure: true}}
			},
			wantError: "tls.items[harbor_corp.tld]",
		},
		{
			name: "tls host key with a single label and no port is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"harbor": {Insecure: true}}
			},
			wantError: "tls.items[harbor]",
		},
		{
			name: "tls host key with an empty port is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"harbor.corp.tld:": {Insecure: true}}
			},
			wantError: "tls.items[harbor.corp.tld:]",
		},
		{
			name: "tls host key with port 0 is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"harbor.corp.tld:0": {Insecure: true}}
			},
			wantError: "tls.items[harbor.corp.tld:0]",
		},
		{
			name: "tls host key with port 65536 is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"harbor.corp.tld:65536": {Insecure: true}}
			},
			wantError: "tls.items[harbor.corp.tld:65536]",
		},
		{
			name: "tls host key with userinfo is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"user@harbor.corp.tld": {Insecure: true}}
			},
			wantError: "tls.items[user@harbor.corp.tld]",
		},
		{
			name: "tls host key with a query is rejected",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"harbor.corp.tld?x": {Insecure: true}}
			},
			wantError: "tls.items[harbor.corp.tld?x]",
		},
		{
			name: "tls host key localhost with a port is valid",
			mutate: func(c *Config) {
				c.TLS.Items = map[string]TLSEntry{"localhost:5000": {Insecure: true}}
			},
		},
		{
			name: "tls errors are reported along with the other validation errors",
			mutate: func(c *Config) {
				c.Mirroring.Platforms = nil
				c.TLS.Default = TLSEntry{Insecure: true}
			},
			wantError:     "Platforms",
			alsoWantError: "tls.default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadDefault()
			if err != nil {
				t.Fatalf("LoadDefault: %v", err)
			}
			tt.mutate(cfg)
			err = cfg.Validate()
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantError)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("expected error containing %q, got %q", tt.wantError, err.Error())
			}
			if !strings.Contains(err.Error(), tt.alsoWantError) {
				t.Fatalf("expected error containing %q, got %q", tt.alsoWantError, err.Error())
			}
		})
	}
}

func TestLoad_TLS(t *testing.T) {
	t.Run("default config has no tls entry", func(t *testing.T) {
		cfg, err := LoadDefault()
		if err != nil {
			t.Fatalf("LoadDefault: %v", err)
		}
		if cfg.TLS.Default.CASecretRef != nil || cfg.TLS.Default.Insecure || len(cfg.TLS.Items) != 0 {
			t.Fatalf("expected an empty tls config, got %+v", cfg.TLS)
		}
	})

	cfg := loadYAML(t, `
tls:
  default:
    caSecretRef:
      namespace: kuik-system
      name: corporate-ca
  items:
    harbor.corp.tld:
      caSecretRef:
        namespace: kuik-system
        name: harbor-ca
    registry.lab.tld:5000:
      insecure: true
    quay.corp.tld:
      caSecretRef:
        namespace: kuik-system
        name: quay-ca
        key: bundle.pem
`)

	t.Run("caSecretRef key defaults to ca.crt in default", func(t *testing.T) {
		want := CASecretRef{Namespace: "kuik-system", Name: "corporate-ca", Key: "ca.crt"}
		if got := cfg.TLS.Default.CASecretRef; got == nil || *got != want {
			t.Fatalf("expected %+v, got %+v", want, got)
		}
	})

	t.Run("caSecretRef key defaults to ca.crt in a host entry", func(t *testing.T) {
		want := CASecretRef{Namespace: "kuik-system", Name: "harbor-ca", Key: "ca.crt"}
		if got := cfg.TLS.Items["harbor.corp.tld"].CASecretRef; got == nil || *got != want {
			t.Fatalf("expected %+v, got %+v", want, got)
		}
	})

	t.Run("explicit caSecretRef key is kept", func(t *testing.T) {
		want := CASecretRef{Namespace: "kuik-system", Name: "quay-ca", Key: "bundle.pem"}
		if got := cfg.TLS.Items["quay.corp.tld"].CASecretRef; got == nil || *got != want {
			t.Fatalf("expected %+v, got %+v", want, got)
		}
	})

	t.Run("dotted host keys with a port are kept whole", func(t *testing.T) {
		entry, ok := cfg.TLS.Items["registry.lab.tld:5000"]
		if !ok || !entry.Insecure {
			t.Fatalf("expected an insecure entry for registry.lab.tld:5000, got items %+v", cfg.TLS.Items)
		}
		if len(cfg.TLS.Items) != 3 {
			t.Fatalf("expected 3 items, got %+v", cfg.TLS.Items)
		}
	})
}

func loadYAML(t *testing.T, content string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func caRef(namespace, name string) *CASecretRef {
	return &CASecretRef{Namespace: namespace, Name: name, Key: "ca.crt"}
}
