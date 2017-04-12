package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/almighty/almighty-core/auth"
	config "github.com/almighty/almighty-core/configuration"
	"github.com/almighty/almighty-core/controller"
	"github.com/almighty/almighty-core/rest"
	"github.com/almighty/almighty-core/space"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	scopes = []string{"read:test", "admin:test"}
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

func GetUserID(t *testing.T, username string, usersecret string, configuration *config.ConfigurationData) string {
	r := &goa.RequestData{
		Request: &http.Request{Host: "domain.io"},
	}

	tokenEndpoint, err := configuration.GetKeycloakEndpointToken(r)
	require.Nil(t, err)
	userinfoEndpoint, err := configuration.GetKeycloakEndpointUserInfo(r)
	require.Nil(t, err)
	adminEndpoint, err := configuration.GetKeycloakEndpointAdmin(r)
	require.Nil(t, err)

	ctx := context.Background()
	testToken, err := controller.GenerateUserToken(ctx, tokenEndpoint, configuration, username, usersecret)
	require.Nil(t, err)
	accessToken := testToken.Token.AccessToken
	userinfo, err := auth.GetUserInfo(ctx, userinfoEndpoint, *accessToken)
	require.Nil(t, err)
	userID := userinfo.Sub
	pat := GetProtectedAPITokenOK(t, configuration)
	ok, err := auth.ValidateKeycloakUser(ctx, adminEndpoint, userID, pat)
	require.Nil(t, err)
	require.True(t, ok)
	return userID
}

func CreatePermissionWithPolicy(t *testing.T, configuration *config.ConfigurationData) (*auth.KeycloakPolicy, string) {
	ctx := context.Background()
	pat := GetProtectedAPITokenOK(t, configuration)

	resourceID, _ := CreateResource(t, ctx, pat, configuration)
	clientID, clientsEndpoint := GetClientIDAndEndpoint(t, configuration)
	policyID, policy := CreatePolicy(t, ctx, pat, configuration)
	require.NotNil(t, policy)

	permission := auth.KeycloakPermission{
		Name:             "test-" + uuid.NewV4().String(),
		Type:             auth.PermissionTypeResource,
		Logic:            auth.PolicyLogicPossitive,
		DecisionStrategy: auth.PolicyDecisionStrategyUnanimous,
		// "config":{"resources":"[\"<ResourceID>\"]","applyPolicies":"[\"<PolicyID>\"]"}
		Config: auth.PermissionConfigData{
			Resources:     "[\"" + resourceID + "\"]",
			ApplyPolicies: "[\"" + policyID + "\"]",
		},
	}

	permissionID, err := auth.CreatePermission(ctx, clientsEndpoint, clientID, permission, pat)
	require.Nil(t, err)
	require.NotEqual(t, "", permissionID)

	return &policy, policyID
}

func CreateResource(t *testing.T, ctx context.Context, pat string, configuration *config.ConfigurationData) (string, string) {
	r := &goa.RequestData{
		Request: &http.Request{Host: "domain.io"},
	}
	uri := "testResourceURI"
	kcResource := auth.KeycloakResource{
		Name:   "test-" + uuid.NewV4().String(),
		Type:   "testResource",
		URI:    &uri,
		Scopes: &scopes,
	}
	authzEndpoint, err := configuration.GetKeycloakEndpointAuthzResourceset(r)
	require.Nil(t, err)

	id, err := auth.CreateResource(ctx, kcResource, authzEndpoint, pat)
	require.Nil(t, err)
	require.NotEqual(t, "", id)
	return id, kcResource.Name
}

func CreatePolicy(t *testing.T, ctx context.Context, pat string, configuration *config.ConfigurationData) (string, auth.KeycloakPolicy) {
	firstTestUserID := GetUserID(t, configuration.GetKeycloakTestUserName(), configuration.GetKeycloakTestUserSecret(), configuration)
	secondTestUserID := GetUserID(t, configuration.GetKeycloakTestUser2Name(), configuration.GetKeycloakTestUser2Secret(), configuration)
	policy := auth.KeycloakPolicy{
		Name:             "test-" + uuid.NewV4().String(),
		Type:             auth.PolicyTypeUser,
		Logic:            auth.PolicyLogicPossitive,
		DecisionStrategy: auth.PolicyDecisionStrategyUnanimous,
	}
	assert.True(t, policy.AddUserToPolicy(firstTestUserID))
	assert.True(t, policy.AddUserToPolicy(secondTestUserID))

	clientID, clientsEndpoint := GetClientIDAndEndpoint(t, configuration)

	id, err := auth.CreatePolicy(ctx, clientsEndpoint, clientID, policy, pat)
	require.Nil(t, err)
	require.NotEqual(t, "", id)
	return id, policy
}

func CreateSpaceResource(t *testing.T, configuration *config.ConfigurationData) space.Resource {
	ctx := context.Background()
	pat := GetProtectedAPITokenOK(t, configuration)

	resourceID, _ := CreateResource(t, ctx, pat, configuration)
	clientID, clientsEndpoint := GetClientIDAndEndpoint(t, configuration)
	policyID, policy := CreatePolicy(t, ctx, pat, configuration)
	require.NotNil(t, policy)

	permission := auth.KeycloakPermission{
		Name:             "test-" + uuid.NewV4().String(),
		Type:             auth.PermissionTypeResource,
		Logic:            auth.PolicyLogicPossitive,
		DecisionStrategy: auth.PolicyDecisionStrategyUnanimous,
		// "config":{"resources":"[\"<ResourceID>\"]","applyPolicies":"[\"<PolicyID>\"]"}
		Config: auth.PermissionConfigData{
			Resources:     "[\"" + resourceID + "\"]",
			ApplyPolicies: "[\"" + policyID + "\"]",
		},
	}

	permissionID, err := auth.CreatePermission(ctx, clientsEndpoint, clientID, permission, pat)
	require.Nil(t, err)
	require.NotEqual(t, "", permissionID)

	return space.Resource{ResourceID: resourceID, PermissionID: permissionID, PolicyID: policyID}
}
