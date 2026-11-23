package config

import (
	"errors"
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

// SecretSync holds encrypted blobs and public keys for a number of key vaults that have external data populated into them.
type SecretSync struct {
	// KeyVaults stores the data for each key vault keyed by the connection URI, like "my-key-vault.azure-test.net".
	// As the connection URI contains a tenant-unique name and a tenant-specific domain, these are globally unique.
	KeyVaults map[string]KeyVault `json:"keyVaults"`
}

// KeyVault holds encrypted data that should be populated into a key vault and the public key used to encrypt these data.
type KeyVault struct {
	// KeyEncryptionKey holds the public half of the key encryption key in PEM block format.
	KeyEncryptionKey string `json:"keyEncryptionKey"`

	// EncryptedSecrets stores Azure Key Vault secret data by secret name that should be populated into the KeyVault.
	// These data are base64-encoded to be easy to embed into this text-based data format.
	EncryptedSecrets map[string]EncryptedSecret `json:"encryptedSecrets"`

	// RetiredSecrets lists names of secrets that must no longer exist in the KeyVault. Populating the KeyVault
	// deletes each of them; a secret that is already absent counts as deleted. With soft-delete enabled, a deleted
	// secret stays recoverable until it is purged, and its name cannot be populated again until then.
	RetiredSecrets []string `json:"retiredSecrets,omitempty"`
}

// Validate checks that each retired secret is named, listed once, and not also declared in EncryptedSecrets,
// since populating would otherwise write the secret and then delete it again on every run.
func (k KeyVault) Validate() error {
	retired := make(map[string]struct{}, len(k.RetiredSecrets))
	for _, name := range k.RetiredSecrets {
		if name == "" {
			return errors.New("retiredSecrets must not contain an empty name")
		}
		if _, duplicate := retired[name]; duplicate {
			return fmt.Errorf("secret %s is listed more than once in retiredSecrets", name)
		}
		if _, declared := k.EncryptedSecrets[name]; declared {
			return fmt.Errorf("secret %s is declared in encryptedSecrets and listed in retiredSecrets", name)
		}
		retired[name] = struct{}{}
	}
	return nil
}

type EncryptedSecret struct {
	// DataEncryptionKey holds the key used to encrypt the data; the key is itself encrypted using the key encryption key.
	// This key may only be used once; the lifetime of the key is the same as the lifetime of the data being encrypted.
	// This encrypted data is base64-encoded to be easy to embed into this text-based data format.
	DataEncryptionKey string `json:"dataEncryptionKey"`

	// Data holds the encrypted secret data that needs to be populated into KeyVault.
	// This encrypted data is base64-encoded to be easy to embed into this text-based data format.
	Data string `json:"data"`
}

func Load(path string) (*SecretSync, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var out SecretSync
	return &out, yaml.Unmarshal(raw, &out)
}
