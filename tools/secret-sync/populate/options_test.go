package populate

import (
	"context"
	"net/http"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/require"

	"github.com/Azure/ARO-Tools/tools/secret-sync/config"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets/fake"
)

func TestPopulateDeletesRetiredSecrets(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		errorCode string
		wantErr   string
	}{
		{name: "existing secret is deleted", status: http.StatusOK},
		{name: "absent secret counts as deleted", status: http.StatusNotFound, errorCode: "SecretNotFound"},
		{name: "rejected delete fails", status: http.StatusForbidden, errorCode: "Forbidden", wantErr: "failed to delete retired secret old-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var deleted []string
			server := fake.Server{
				DeleteSecret: func(_ context.Context, name string, _ *azsecrets.DeleteSecretOptions) (resp azfake.Responder[azsecrets.DeleteSecretResponse], errResp azfake.ErrorResponder) {
					deleted = append(deleted, name)
					if tc.status != http.StatusOK {
						errResp.SetResponseError(tc.status, tc.errorCode)
						return
					}
					resp.SetResponse(http.StatusOK, azsecrets.DeleteSecretResponse{}, nil)
					return
				},
			}
			client, err := azsecrets.NewClient("https://test-vault.vault.azure.net", &azfake.TokenCredential{}, &azsecrets.ClientOptions{
				ClientOptions: azcore.ClientOptions{Transport: fake.NewServerTransport(&server)},
			})
			require.NoError(t, err)

			opts := &Options{completedOptions: &completedOptions{
				KeyVaultURI:   "https://test-vault.vault.azure.net",
				Config:        config.KeyVault{RetiredSecrets: []string{"old-token"}},
				SecretsClient: client,
			}}
			err = opts.Populate(logr.NewContext(t.Context(), testr.New(t)))

			require.Equal(t, []string{"old-token"}, deleted)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}
