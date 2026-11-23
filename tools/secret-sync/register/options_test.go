package register

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/require"

	"sigs.k8s.io/yaml"

	"github.com/Azure/ARO-Tools/tools/cmdutils"
	"github.com/Azure/ARO-Tools/tools/secret-sync/config"
)

func TestRegisterKeepsRetiredSecrets(t *testing.T) {
	const keyVaultURI = "https://test-vault.vault.azure.net"

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "secrets.yaml")
	initial, err := yaml.Marshal(config.SecretSync{KeyVaults: map[string]config.KeyVault{
		keyVaultURI: {
			KeyEncryptionKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey})),
			RetiredSecrets:   []string{"old-token"},
		},
	}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(configFile, initial, 0o600))
	secretFile := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("value"), 0o600))

	register := func(name string) error {
		validated, err := (&RawOptions{
			RawOptions: &cmdutils.RawOptions{Cloud: string(cmdutils.RolloutCloudPublic)},
			KeyVault:   "test-vault",
			ConfigFile: configFile,
			SecretFile: secretFile,
			SecretName: name,
		}).Validate()
		if err != nil {
			return err
		}
		completed, err := validated.Complete()
		if err != nil {
			return err
		}
		return completed.Register(logr.NewContext(t.Context(), testr.New(t)))
	}

	require.ErrorContains(t, register("old-token"), "old-token is listed in retiredSecrets")
	unchanged, err := os.ReadFile(configFile)
	require.NoError(t, err)
	require.Equal(t, string(initial), string(unchanged))

	require.NoError(t, register("new-token"))
	cfg, err := config.Load(configFile)
	require.NoError(t, err)
	require.Contains(t, cfg.KeyVaults[keyVaultURI].EncryptedSecrets, "new-token")
	require.Equal(t, []string{"old-token"}, cfg.KeyVaults[keyVaultURI].RetiredSecrets, "rewriting the config must keep retiredSecrets")
}
