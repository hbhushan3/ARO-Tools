package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyVaultValidate(t *testing.T) {
	declared := map[string]EncryptedSecret{"current-token": {DataEncryptionKey: "key", Data: "data"}}
	for _, tc := range []struct {
		name    string
		retired []string
		wantErr string
	}{
		{name: "distinct undeclared names", retired: []string{"old-token", "older-token"}},
		{name: "empty name", retired: []string{""}, wantErr: "must not contain an empty name"},
		{name: "duplicate name", retired: []string{"old-token", "old-token"}, wantErr: "old-token is listed more than once"},
		{name: "declared and retired", retired: []string{"current-token"}, wantErr: "current-token is declared in encryptedSecrets and listed in retiredSecrets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := KeyVault{EncryptedSecrets: declared, RetiredSecrets: tc.retired}.Validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}
