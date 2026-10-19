package registry

import (
	"context"
	"fmt"

	"github.com/enix/kube-image-keeper/internal/config"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// LoadTLSSettings builds the TLS settings of the registry clients from the tls
// configuration, reading its CA Secrets through reader. Called each time a
// client is built, so that a change of a CA Secret applies without a restart.
// A CA Secret that cannot be read does not fail the settings: the bundle carries
// the error, and every request to the hosts it applies to fails with it.
func LoadTLSSettings(ctx context.Context, reader client.Reader, cfg *config.TLS) *TLSSettings {
	settings := &TLSSettings{}
	if cfg == nil {
		return settings
	}
	settings.Default = loadTLSEntry(ctx, reader, cfg.Default)
	if len(cfg.Items) > 0 {
		settings.Items = make(map[string]TLSEntry, len(cfg.Items))
		for host, entry := range cfg.Items {
			settings.Items[host] = loadTLSEntry(ctx, reader, entry)
		}
	}
	return settings
}

func loadTLSEntry(ctx context.Context, reader client.Reader, entry config.TLSEntry) TLSEntry {
	loaded := TLSEntry{Insecure: entry.Insecure}
	if entry.CASecretRef != nil {
		loaded.CAs = []CABundle{loadCABundle(ctx, reader, entry.CASecretRef)}
	}
	return loaded
}

func loadCABundle(ctx context.Context, reader client.Reader, ref *config.CASecretRef) CABundle {
	key := ref.Key
	if key == "" {
		key = config.DefaultCASecretKey
	}
	bundle := CABundle{Source: fmt.Sprintf("Secret %s/%s, key %s", ref.Namespace, ref.Name, key)}

	secret := &corev1.Secret{}
	if err := reader.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, secret); err != nil {
		bundle.Err = fmt.Errorf("could not read the Secret: %w", err)
		return bundle
	}
	data, ok := secret.Data[key]
	if !ok {
		bundle.Err = fmt.Errorf("the Secret has no key %q", key)
		return bundle
	}
	bundle.PEM = data
	return bundle
}
