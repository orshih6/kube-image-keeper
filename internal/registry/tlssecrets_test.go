package registry

import (
	"context"
	"strings"
	"testing"

	"github.com/enix/kube-image-keeper/internal/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func caSecret(name, key string, data []byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kuik-system", Name: name},
		Data:       map[string][]byte{key: data},
	}
}

func caSecretRef(name, key string) *config.CASecretRef {
	return &config.CASecretRef{Namespace: "kuik-system", Name: name, Key: key}
}

// onlyCA returns the single CA bundle of an entry.
func onlyCA(t *testing.T, entry TLSEntry) CABundle {
	t.Helper()
	if len(entry.CAs) != 1 {
		t.Fatalf("expected 1 CA bundle, got %+v", entry.CAs)
	}
	return entry.CAs[0]
}

func loadSettings(t *testing.T, reader client.Reader, cfg *config.TLS) *TLSSettings {
	t.Helper()
	s := LoadTLSSettings(context.Background(), reader, cfg)
	if s == nil {
		t.Fatal("expected TLS settings, got nil")
	}
	return s
}

func TestLoadTLSSettings(t *testing.T) {
	t.Run("the CA of a caSecretRef is read from the key of its Secret", func(t *testing.T) {
		reader := fake.NewClientBuilder().WithObjects(
			caSecret("corporate-ca", "ca.crt", []byte("corporate PEM")),
			caSecret("harbor-ca", "bundle.pem", []byte("harbor PEM")),
		).Build()
		s := loadSettings(t, reader, &config.TLS{
			Default: config.TLSEntry{CASecretRef: caSecretRef("corporate-ca", "ca.crt")},
			Items: map[string]config.TLSEntry{
				"harbor.corp.tld": {CASecretRef: caSecretRef("harbor-ca", "bundle.pem")},
			},
		})

		defaultCA := onlyCA(t, s.Default)
		if defaultCA.Err != nil || string(defaultCA.PEM) != "corporate PEM" {
			t.Errorf("default CA = %+v, want the corporate PEM", defaultCA)
		}
		if want := "Secret kuik-system/corporate-ca, key ca.crt"; defaultCA.Source != want {
			t.Errorf("default CA source = %q, want %q", defaultCA.Source, want)
		}
		hostCA := onlyCA(t, s.Items["harbor.corp.tld"])
		if hostCA.Err != nil || string(hostCA.PEM) != "harbor PEM" {
			t.Errorf("host CA = %+v, want the harbor PEM", hostCA)
		}
		if want := "Secret kuik-system/harbor-ca, key bundle.pem"; hostCA.Source != want {
			t.Errorf("host CA source = %q, want %q", hostCA.Source, want)
		}
	})

	t.Run("a missing CA Secret gives a CA error naming the Secret", func(t *testing.T) {
		s := loadSettings(t, fake.NewClientBuilder().Build(), &config.TLS{
			Items: map[string]config.TLSEntry{"harbor.corp.tld": {CASecretRef: caSecretRef("harbor-ca", "ca.crt")}},
		})

		ca := onlyCA(t, s.Items["harbor.corp.tld"])
		if ca.Err == nil || !strings.Contains(ca.Err.Error(), "not found") {
			t.Errorf("expected a not found error, got %v", ca.Err)
		}
		if !strings.Contains(ca.Source, "Secret kuik-system/harbor-ca") {
			t.Errorf("expected the source to name the Secret, got %q", ca.Source)
		}
	})

	t.Run("a CA Secret without the key gives a CA error naming the Secret and the key", func(t *testing.T) {
		reader := fake.NewClientBuilder().WithObjects(caSecret("harbor-ca", "tls.crt", []byte("PEM"))).Build()
		s := loadSettings(t, reader, &config.TLS{
			Items: map[string]config.TLSEntry{"harbor.corp.tld": {CASecretRef: caSecretRef("harbor-ca", "ca.crt")}},
		})

		ca := onlyCA(t, s.Items["harbor.corp.tld"])
		if ca.Err == nil || !strings.Contains(ca.Err.Error(), `no key "ca.crt"`) {
			t.Errorf("expected a missing key error, got %v", ca.Err)
		}
		if want := "Secret kuik-system/harbor-ca, key ca.crt"; ca.Source != want {
			t.Errorf("source = %q, want %q", ca.Source, want)
		}
	})

	t.Run("an insecure host entry is kept", func(t *testing.T) {
		s := loadSettings(t, fake.NewClientBuilder().Build(), &config.TLS{
			Items: map[string]config.TLSEntry{"registry.lab.tld:5000": {Insecure: true}},
		})

		entry, ok := s.Items["registry.lab.tld:5000"]
		if !ok || !entry.Insecure || len(entry.CAs) != 0 {
			t.Errorf("expected an insecure entry without CA, got %+v (present: %v)", entry, ok)
		}
	})

	t.Run("a change of a CA Secret is read by the next call", func(t *testing.T) {
		secret := caSecret("corporate-ca", "ca.crt", []byte("old PEM"))
		reader := fake.NewClientBuilder().WithObjects(secret).Build()
		cfg := &config.TLS{Default: config.TLSEntry{CASecretRef: caSecretRef("corporate-ca", "ca.crt")}}
		_ = loadSettings(t, reader, cfg)

		secret.Data["ca.crt"] = []byte("new PEM")
		if err := reader.Update(context.Background(), secret); err != nil {
			t.Fatalf("update Secret: %v", err)
		}

		if ca := onlyCA(t, loadSettings(t, reader, cfg).Default); string(ca.PEM) != "new PEM" {
			t.Errorf("expected the new PEM, got %q", ca.PEM)
		}
	})
}
