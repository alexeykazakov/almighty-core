package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/almighty/almighty-core/auth"
	config "github.com/almighty/almighty-core/configuration"
	"github.com/almighty/almighty-core/controller"
	"github.com/almighty/almighty-core/errors"
	"github.com/almighty/almighty-core/resource"
	"github.com/almighty/almighty-core/rest"
	authtest "github.com/almighty/almighty-core/test/auth"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"strings"

	_ "github.com/lib/pq"
)

var (
	configuration *config.ConfigurationData
	scopes        = []string{"read:test", "admin:test"}
)

func init() {
	var err error
	configuration, err = config.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
}

func TestAuth(t *testing.T) {
	resource.Require(t, resource.Remote)
	suite.Run(t, new(TestAuthSuite))
}

type TestAuthSuite struct {
	suite.Suite
}

func (s *TestAuthSuite) SetupSuite() {
}

func (s *TestAuthSuite) TearDownSuite() {
	CleanKeycloakResources(s.T())
}

func (s *TestAuthSuite) TestCreateAndDeleteResourceOK() {
	r := &goa.RequestData{
		Request: &http.Request{Host: "domain.io"},
	}
	ctx := context.Background()
	authzEndpoint, err := configuration.GetKeycloakEndpointAuthzResourceset(r)
	require.Nil(s.T(), err)
	pat := authtest.GetProtectedAPITokenOK(s.T(), configuration)

	id, _ := authtest.CreateResource(s.T(), ctx, pat, configuration)
	authtest.DeleteResource(s.T(), ctx, id, authzEndpoint, pat)
}

func (s *TestAuthSuite) TestDeleteNonexistingResourceFails() {
	r := &goa.RequestData{
		Request: &http.Request{Host: "domain.io"},
	}

	ctx := context.Background()

	authzEndpoint, err := configuration.GetKeycloakEndpointAuthzResourceset(r)
	require.Nil(s.T(), err)
	pat := authtest.GetProtectedAPITokenOK(s.T(), configuration)
	err = auth.DeleteResource(ctx, uuid.NewV4().String(), authzEndpoint, pat)
	require.NotNil(s.T(), err)
}

func (s *TestAuthSuite) TestCreatePolicyOK() {
	ctx := context.Background()
	pat := authtest.GetProtectedAPITokenOK(s.T(), configuration)
	clientId, clientsEndpoint := authtest.GetClientIDAndEndpoint(s.T(), configuration)

	id, policy := authtest.CreatePolicy(s.T(), ctx, pat, configuration)
	defer authtest.DeletePolicy(s.T(), ctx, clientsEndpoint, clientId, id, pat)

	pl := validatePolicy(s.T(), ctx, clientsEndpoint, clientId, policy, id, pat)

	firstTestUserID := authtest.GetUserID(s.T(), configuration.GetKeycloakTestUserName(), configuration.GetKeycloakTestUserSecret(), configuration)
	pl.Config = auth.PolicyConfigData{
		UserIDs: "[\"" + firstTestUserID + "\"]",
	}
	err := auth.UpdatePolicy(ctx, clientsEndpoint, clientId, *pl, pat)
	require.Nil(s.T(), err)
	validatePolicy(s.T(), ctx, clientsEndpoint, clientId, *pl, id, pat)
}

func (s *TestAuthSuite) TestDeletePolicyOK() {
	ctx := context.Background()
	pat := authtest.GetProtectedAPITokenOK(s.T(), configuration)
	clientId, clientsEndpoint := authtest.GetClientIDAndEndpoint(s.T(), configuration)

	id, _ := authtest.CreatePolicy(s.T(), ctx, pat, configuration)
	authtest.DeletePolicy(s.T(), ctx, clientsEndpoint, clientId, id, pat)

	_, err := auth.GetPolicy(ctx, clientsEndpoint, clientId, id, pat)
	require.NotNil(s.T(), err)
	require.IsType(s.T(), errors.NotFoundError{}, err)
}

func (s *TestAuthSuite) TestCreateAndDeletePermissionOK() {
	r := &goa.RequestData{
		Request: &http.Request{Host: "domain.io"},
	}
	authzEndpoint, err := configuration.GetKeycloakEndpointAuthzResourceset(r)
	require.Nil(s.T(), err)

	ctx := context.Background()
	pat := authtest.GetProtectedAPITokenOK(s.T(), configuration)

	resourceID, _ := authtest.CreateResource(s.T(), ctx, pat, configuration)
	defer authtest.DeleteResource(s.T(), ctx, resourceID, authzEndpoint, pat)
	clientId, clientsEndpoint := authtest.GetClientIDAndEndpoint(s.T(), configuration)
	policyID, _ := authtest.CreatePolicy(s.T(), ctx, pat, configuration)
	defer authtest.DeletePolicy(s.T(), ctx, clientsEndpoint, clientId, policyID, pat)

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

	id, err := auth.CreatePermission(ctx, clientsEndpoint, clientId, permission, pat)
	require.Nil(s.T(), err)
	require.NotEqual(s.T(), "", id)
	deletePermission(s.T(), ctx, clientsEndpoint, clientId, id, pat)
}

func (s *TestAuthSuite) TestDeleteNonexistingPolicyAndPermissionFails() {
	r := &goa.RequestData{
		Request: &http.Request{Host: "domain.io"},
	}

	ctx := context.Background()

	clientsEndpoint, err := configuration.GetKeycloakEndpointClients(r)
	require.Nil(s.T(), err)
	pat := authtest.GetProtectedAPITokenOK(s.T(), configuration)
	clientId, _ := authtest.GetClientIDAndEndpoint(s.T(), configuration)
	err = auth.DeletePolicy(ctx, clientsEndpoint, clientId, uuid.NewV4().String(), pat)
	assert.NotNil(s.T(), err)

	err = auth.DeletePermission(ctx, clientsEndpoint, clientId, uuid.NewV4().String(), pat)
	assert.NotNil(s.T(), err)
}

func (s *TestAuthSuite) TestGetEntitlement() {
	r := &goa.RequestData{
		Request: &http.Request{Host: "domain.io"},
	}
	authzEndpoint, err := configuration.GetKeycloakEndpointAuthzResourceset(r)
	require.Nil(s.T(), err)

	ctx := context.Background()
	pat := authtest.GetProtectedAPITokenOK(s.T(), configuration)

	resourceID, resourceName := authtest.CreateResource(s.T(), ctx, pat, configuration)
	defer authtest.DeleteResource(s.T(), ctx, resourceID, authzEndpoint, pat)
	clientId, clientsEndpoint := authtest.GetClientIDAndEndpoint(s.T(), configuration)
	policyID, _ := authtest.CreatePolicy(s.T(), ctx, pat, configuration)
	defer authtest.DeletePolicy(s.T(), ctx, clientsEndpoint, clientId, policyID, pat)

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

	permissionID, err := auth.CreatePermission(ctx, clientsEndpoint, clientId, permission, pat)
	require.Nil(s.T(), err)
	require.NotEqual(s.T(), "", permissionID)
	defer deletePermission(s.T(), ctx, clientsEndpoint, clientId, permissionID, pat)

	entitlementEndpoint, err := configuration.GetKeycloakEndpointEntitlement(r)
	require.Nil(s.T(), err)
	tokenEndpoint, err := configuration.GetKeycloakEndpointToken(r)
	require.Nil(s.T(), err)
	testUserToken, err := controller.GenerateUserToken(ctx, tokenEndpoint, configuration, configuration.GetKeycloakTestUserName(), configuration.GetKeycloakTestUserSecret())
	// {"permissions" : [{"resource_set_name" : "<spaceID>"}]}
	entitlementResource := auth.EntitlementResource{
		Permissions: []auth.ResourceSet{{Name: resourceName}},
	}
	ent, err := auth.GetEntitlement(ctx, entitlementEndpoint, &entitlementResource, *testUserToken.Token.AccessToken)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), ent)
	require.NotEqual(s.T(), "", ent)

	ok, err := auth.VerifyResourceUser(ctx, *testUserToken.Token.AccessToken, resourceName, entitlementEndpoint)
	require.True(s.T(), ok)
	require.Nil(s.T(), err)

	secondTestUserID := authtest.GetUserID(s.T(), configuration.GetKeycloakTestUser2Name(), configuration.GetKeycloakTestUser2Secret(), configuration)
	pl, err := auth.GetPolicy(ctx, clientsEndpoint, clientId, policyID, pat)
	pl.Config = auth.PolicyConfigData{
		UserIDs: "[\"" + secondTestUserID + "\"]",
	}
	err = auth.UpdatePolicy(ctx, clientsEndpoint, clientId, *pl, pat)
	require.Nil(s.T(), err)

	ent, err = auth.GetEntitlement(ctx, entitlementEndpoint, &entitlementResource, *testUserToken.Token.AccessToken)
	require.Nil(s.T(), err)
	require.Nil(s.T(), ent)

	ok, err = auth.VerifyResourceUser(ctx, *testUserToken.Token.AccessToken, resourceName, entitlementEndpoint)
	require.False(s.T(), ok)
	require.Nil(s.T(), err)

	ent, err = auth.GetEntitlement(ctx, entitlementEndpoint, nil, *testUserToken.Token.AccessToken)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), ent)
	require.NotEqual(s.T(), "", ent)

	ent, err = auth.GetEntitlement(ctx, entitlementEndpoint, nil, *ent)
	require.Nil(s.T(), err)
	require.NotNil(s.T(), ent)
	require.NotEqual(s.T(), "", ent)
}

func (s *TestAuthSuite) TestGetClientIDOK() {
	id, _ := authtest.GetClientIDAndEndpoint(s.T(), configuration)
	assert.Equal(s.T(), "65d23f35-c532-4493-a860-39e851abe397", id)
}

func (s *TestAuthSuite) TestGetProtectedAPITokenOK() {
	token := authtest.GetProtectedAPITokenOK(s.T(), configuration)
	require.NotEqual(s.T(), "", token)
}

func (s *TestAuthSuite) TestReadTokenOK() {
	b := closer{bytes.NewBufferString("{\"access_token\":\"accToken\", \"expires_in\":1, \"refresh_expires_in\":2, \"refresh_token\":\"refToken\"}")}
	response := http.Response{Body: b}
	token, err := auth.ReadToken(&response)
	require.Nil(s.T(), err)
	assert.Equal(s.T(), "accToken", *token.AccessToken)
	assert.Equal(s.T(), 1, *token.ExpiresIn)
	assert.Equal(s.T(), 2, *token.RefreshExpiresIn)
	assert.Equal(s.T(), "refToken", *token.RefreshToken)
}

func (s *TestAuthSuite) TestUpdateUserToPolicyOK() {
	policy := auth.KeycloakPolicy{
		Name:             "test-" + uuid.NewV4().String(),
		Type:             auth.PolicyTypeUser,
		Logic:            auth.PolicyLogicPossitive,
		DecisionStrategy: auth.PolicyDecisionStrategyUnanimous,
	}
	userID1 := uuid.NewV4().String()
	userID2 := uuid.NewV4().String()
	userID3 := uuid.NewV4().String()
	assert.True(s.T(), policy.AddUserToPolicy(userID1))
	//"users":"[\"<ID>\",\"<ID>\"]"
	assert.Equal(s.T(), fmt.Sprintf("[\"%s\"]", userID1), policy.Config.UserIDs)
	assert.True(s.T(), policy.AddUserToPolicy(userID2))
	assert.Equal(s.T(), fmt.Sprintf("[\"%s\",\"%s\"]", userID1, userID2), policy.Config.UserIDs)
	assert.False(s.T(), policy.AddUserToPolicy(userID2))
	assert.Equal(s.T(), fmt.Sprintf("[\"%s\",\"%s\"]", userID1, userID2), policy.Config.UserIDs)
	assert.True(s.T(), policy.AddUserToPolicy(userID3))
	assert.Equal(s.T(), fmt.Sprintf("[\"%s\",\"%s\",\"%s\"]", userID1, userID2, userID3), policy.Config.UserIDs)
	assert.False(s.T(), policy.RemoveUserFromPolicy(uuid.NewV4().String()))
	assert.Equal(s.T(), fmt.Sprintf("[\"%s\",\"%s\",\"%s\"]", userID1, userID2, userID3), policy.Config.UserIDs)
	assert.True(s.T(), policy.RemoveUserFromPolicy(userID2))
	assert.Equal(s.T(), fmt.Sprintf("[\"%s\",\"%s\"]", userID1, userID3), policy.Config.UserIDs)
	assert.True(s.T(), policy.RemoveUserFromPolicy(userID1))
	assert.Equal(s.T(), fmt.Sprintf("[\"%s\"]", userID3), policy.Config.UserIDs)
	assert.True(s.T(), policy.AddUserToPolicy(userID2))
	assert.Equal(s.T(), fmt.Sprintf("[\"%s\",\"%s\"]", userID3, userID2), policy.Config.UserIDs)
	assert.True(s.T(), policy.RemoveUserFromPolicy(userID3))
	assert.Equal(s.T(), fmt.Sprintf("[\"%s\"]", userID2), policy.Config.UserIDs)
	assert.True(s.T(), policy.RemoveUserFromPolicy(userID2))
	assert.Equal(s.T(), "[]", policy.Config.UserIDs)
}

func CleanKeycloakResources(t *testing.T) {
	r := &goa.RequestData{
		Request: &http.Request{Host: "domain.io"},
	}
	ctx := context.Background()
	authzEndpoint, err := configuration.GetKeycloakEndpointAuthzResourceset(r)
	require.Nil(t, err)

	clientId, clientsEndpoint := authtest.GetClientIDAndEndpoint(t, configuration)
	resourceEndpoint := clientsEndpoint + "/" + clientId + "/authz/resource-server/resource?deep=false&first=0&max=1000"
	pat := authtest.GetProtectedAPITokenOK(t, configuration)

	req, err := http.NewRequest("GET", resourceEndpoint, nil)
	require.Nil(t, err)
	req.Header.Add("Authorization", "Bearer "+pat)
	res, err := http.DefaultClient.Do(req)
	require.Nil(t, err)
	require.Equal(t, 200, res.StatusCode)

	jsonString := rest.ReadBody(res.Body)

	var result []authtest.ResourceRequestResultPayload
	err = json.Unmarshal([]byte(jsonString), &result)
	require.Nil(t, err)
	for _, res := range result {
		if strings.Contains(strings.ToLower(res.Uri), "test") {
			authtest.DeleteResource(t, ctx, res.ID, authzEndpoint, pat)
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
	var policyResult []authtest.PolicyRequestResultPayload
	err = json.Unmarshal([]byte(jsonString), &policyResult)
	require.Nil(t, err)
	for _, policy := range policyResult {
		if strings.Contains(strings.ToLower(policy.Name), "test") {
			authtest.DeletePolicy(t, ctx, clientsEndpoint, clientId, policy.ID, pat)
		}
	}
}

func deletePermission(t *testing.T, ctx context.Context, clientsEndpoint string, clientId string, id string, pat string) {
	err := auth.DeletePermission(ctx, clientsEndpoint, clientId, id, pat)
	assert.Nil(t, err)
}

func validatePolicy(t *testing.T, ctx context.Context, clientsEndpoint string, clientId string, policyToValidate auth.KeycloakPolicy, remotePolicyId string, pat string) *auth.KeycloakPolicy {
	pl, err := auth.GetPolicy(ctx, clientsEndpoint, clientId, remotePolicyId, pat)
	assert.Nil(t, err)
	assert.Equal(t, policyToValidate.Name, pl.Name)
	assert.Equal(t, policyToValidate.Type, pl.Type)
	assert.Equal(t, policyToValidate.Logic, pl.Logic)
	assert.Equal(t, policyToValidate.Type, pl.Type)
	assert.Equal(t, policyToValidate.DecisionStrategy, pl.DecisionStrategy)
	assert.Equal(t, policyToValidate.Config.UserIDs, pl.Config.UserIDs)
	return pl
}

type closer struct {
	io.Reader
}

func (closer) Close() error {
	return nil
}
