package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/almighty/almighty-core/auth"
	config "github.com/almighty/almighty-core/configuration"
	"github.com/almighty/almighty-core/rest"
	"github.com/goadesign/goa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ResourceRequestResultPayload struct {
	Name string `json:"name"`
	Uri  string `json:"uri"`
	ID   string `json:"_id"`
}

type PolicyRequestResultPayload struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

func DeleteResource(t *testing.T, ctx context.Context, id string, authzEndpoint string, pat string) {
	err := auth.DeleteResource(ctx, id, authzEndpoint, pat)
	assert.Nil(t, err)
}

func GetProtectedAPITokenOK(t *testing.T, configuration *config.ConfigurationData) string {
	r := &goa.RequestData{
		Request: &http.Request{Host: "demo.api.almighty.io"},
	}

	endpoint, err := configuration.GetKeycloakEndpointToken(r)
	require.Nil(t, err)
	token, err := auth.GetProtectedAPIToken(endpoint, configuration.GetKeycloakClientID(), configuration.GetKeycloakSecret())
	require.Nil(t, err)
	return token
}

func GetClientIDAndEndpoint(t *testing.T, configuration *config.ConfigurationData) (string, string) {
	r := &goa.RequestData{
		Request: &http.Request{Host: "domain.io"},
	}
	clientsEndpoint, err := configuration.GetKeycloakEndpointClients(r)
	require.Nil(t, err)
	publicClientID := configuration.GetKeycloakClientID()
	require.Nil(t, err)
	pat := GetProtectedAPITokenOK(t, configuration)

	id, err := auth.GetClientID(context.Background(), clientsEndpoint, publicClientID, pat)
	require.Nil(t, err)
	return id, clientsEndpoint
}

func DeletePolicy(t *testing.T, ctx context.Context, clientsEndpoint string, clientId string, id string, pat string) {
	err := auth.DeletePolicy(ctx, clientsEndpoint, clientId, id, pat)
	assert.Nil(t, err)
}

func CleanKeycloakResources(t *testing.T, configuration *config.ConfigurationData) {
	r := &goa.RequestData{
		Request: &http.Request{Host: "domain.io"},
	}
	ctx := context.Background()
	authzEndpoint, err := configuration.GetKeycloakEndpointAuthzResourceset(r)
	require.Nil(t, err)

	clientId, clientsEndpoint := GetClientIDAndEndpoint(t, configuration)
	resourceEndpoint := clientsEndpoint + "/" + clientId + "/authz/resource-server/resource?deep=false&first=0&max=1000"
	pat := GetProtectedAPITokenOK(t, configuration)

	req, err := http.NewRequest("GET", resourceEndpoint, nil)
	require.Nil(t, err)
	req.Header.Add("Authorization", "Bearer "+pat)
	res, err := http.DefaultClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, 200, res.StatusCode)

	jsonString := rest.ReadBody(res.Body)

	var result []ResourceRequestResultPayload
	err = json.Unmarshal([]byte(jsonString), &result)
	require.Nil(t, err)
	for _, res := range result {
		if strings.Contains(strings.ToLower(res.Uri), "test") {
			DeleteResource(t, ctx, res.ID, authzEndpoint, pat)
		}
	}

	policyEndpoint := clientsEndpoint + "/" + clientId + "/authz/resource-server/policy?first=0&max=1000&permission=false"
	req, err = http.NewRequest("GET", policyEndpoint, nil)
	require.Nil(t, err)
	req.Header.Add("Authorization", "Bearer "+pat)
	res, err = http.DefaultClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, 200, res.StatusCode)

	jsonString = rest.ReadBody(res.Body)
	var policyResult []PolicyRequestResultPayload
	err = json.Unmarshal([]byte(jsonString), &policyResult)
	require.Nil(t, err)
	for _, policy := range policyResult {
		if strings.Contains(strings.ToLower(policy.Name), "test") {
			DeletePolicy(t, ctx, clientsEndpoint, clientId, policy.ID, pat)
		}
	}
}
