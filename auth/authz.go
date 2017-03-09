package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/almighty/almighty-core/app"
	"github.com/almighty/almighty-core/errors"
	"github.com/almighty/almighty-core/log"
	"github.com/almighty/almighty-core/rest"
)

const (
	// PermissionTypeResource is to used in a Keycloak Permission payload: {"type":"resource"}
	PermissionTypeResource = "resource"
	// PolicyTypeUser is to used in a Keycloak Policy payload: {"type":"user"}
	PolicyTypeUser = "user"
	// PolicyLogicPossitive is to used in a Keycloak Policy payload: {"logic":""POSITIVE"}
	PolicyLogicPossitive = "POSITIVE"
	// PolicyDecisionStrategyUnanimous is to used in a Keycloak Policy payload: {"decisionStrategy":""UNANIMOUS"}
	PolicyDecisionStrategyUnanimous = "UNANIMOUS"
)

// KeycloakResource represents a keyclaok resource payload
type KeycloakResource struct {
	Name   string    `json:"name"`
	Owner  *string   `json:"owner,omitempty"`
	Type   string    `json:"type"`
	Scopes *[]string `json:"scopes,omitempty"`
	URI    *string   `json:"uri,omitempty"`
}

type creteResourceRequestResultPayload struct {
	ID string `json:"_id"`
}

type cretePolicyRequestResultPayload struct {
	ID string `json:"id"`
}

type clientData struct {
	ID       string `json:"id"`
	ClientID string `json:"clientID"`
}

// KeycloakPolicy represents a keyclaok policy payload
type KeycloakPolicy struct {
	ID               *string          `json:"id,omitempty"`
	Name             string           `json:"name"`
	Type             string           `json:"type"`
	Logic            string           `json:"logic"`
	DecisionStrategy string           `json:"decisionStrategy"`
	Config           PolicyConfigData `json:"config"`
}

// PolicyConfigData represents a config in the keyclaok policy payload
type PolicyConfigData struct {
	UserIDs string `json:"users"`
}

// KeycloakPermission represents a keyclaok permission payload
type KeycloakPermission struct {
	ID               *string              `json:"id,omitempty"`
	Name             string               `json:"name"`
	Type             string               `json:"type"`
	Logic            string               `json:"logic"`
	DecisionStrategy string               `json:"decisionStrategy"`
	Config           PermissionConfigData `json:"config"`
}

// PermissionConfigData represents a config in the keyclaok permission payload
type PermissionConfigData struct {
	Resources     string `json:"resources"`
	ApplyPolicies string `json:"applyPolicies"`
}

// UserInfo represents a user info Keycloak payload
type UserInfo struct {
	Sub               string `json:"sub"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
	Email             string `json:"email"`
}

// EntitlementResource represents a payload for obtaining entitlement for specific resource
type EntitlementResource struct {
	Permissions []ResourceSet `json:"permissions"`
}

// ResourceSet represents a resource set for Entitlement payload
type ResourceSet struct {
	Name string  `json:"resource_set_name"`
	ID   *string `json:"resource_set_id,omitempty"`
}

type entitlementResult struct {
	Rpt string `json:"rpt"`
}

// CreateResource creates a Keycloak resource
func CreateResource(ctx context.Context, resource KeycloakResource, authzEndpoint string, protectionAPIToken string) (string, error) {
	log.Debug(ctx, map[string]interface{}{
		"resource": resource,
	}, "Creating a new Keycloak resource")

	b, err := json.Marshal(resource)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource": resource,
			"err":      err.Error(),
		}, "Unable to marshal keyclaok resource struct")
		return "", errors.NewInternalError("unable to marshal keyclaok resource struct " + err.Error())
	}

	req, err := http.NewRequest("POST", authzEndpoint, strings.NewReader(string(b)))
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to crete http request")
		return "", errors.NewInternalError("unable to crete http request " + err.Error())
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+protectionAPIToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource": resource,
			"err":      err.Error(),
		}, "Unable to create a Keycloak resource")
		return "", errors.NewInternalError("Unable to create a Keycloak resource " + err.Error())
	}
	if res.StatusCode != 201 {
		log.Error(ctx, map[string]interface{}{
			"resource":       resource,
			"responceStatus": res.Status,
			"responceBody":   rest.ReadBody(res.Body),
		}, "Unable to create a Keycloak resource")
		return "", errors.NewInternalError("Unable to create a Keycloak resource. Response status: " + res.Status + ". Responce body: " + rest.ReadBody(res.Body))
	}
	jsonString := rest.ReadBody(res.Body)

	var r creteResourceRequestResultPayload
	err = json.Unmarshal([]byte(jsonString), &r)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"resource":   resource,
			"jsonString": jsonString,
		}, "Unable to unmarshal json with the create keycloak resource request result")

		return "", errors.NewInternalError(fmt.Sprintf("Unable to unmarshal json with the create keycloak resource request result %s ", jsonString) + err.Error())
	}

	log.Debug(ctx, map[string]interface{}{
		"resourceName": resource.Name,
		"resourceID":   r.ID,
	}, "Keycloak resource created")

	return r.ID, nil
}

// GetClientID obtains the internal client ID associated with keycloak client
func GetClientID(ctx context.Context, clientsEndpoint string, publicClientID string, protectionAPIToken string) (string, error) {
	req, err := http.NewRequest("GET", clientsEndpoint, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to crete http request")
		return "", errors.NewInternalError("unable to crete http request " + err.Error())
	}
	req.Header.Add("Authorization", "Bearer "+protectionAPIToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"publicClientID": publicClientID,
			"err":            err.Error(),
		}, "Unable to obtain keycloak client ID")
		return "", errors.NewInternalError("Unable to obtain keycloak client ID " + err.Error())
	}
	if res.StatusCode != 200 {
		log.Error(ctx, map[string]interface{}{
			"publicClientID": publicClientID,
			"responceStatus": res.Status,
			"responceBody":   rest.ReadBody(res.Body),
		}, "Unable to obtain keycloak client ID")
		return "", errors.NewInternalError("Unable to obtain keycloak client ID. Response status: " + res.Status + ". Responce body: " + rest.ReadBody(res.Body))
	}
	jsonString := rest.ReadBody(res.Body)

	var r []clientData
	err = json.Unmarshal([]byte(jsonString), &r)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"publicClientID": publicClientID,
			"err":            err.Error(),
		}, "Unable to unmarshal json with client ID")
		return "", errors.NewInternalError(fmt.Sprintf("error when unmarshal json with client ID result %s ", jsonString) + err.Error())
	}
	for _, client := range r {
		if publicClientID == client.ClientID {
			return client.ID, nil
		}
	}
	log.Error(ctx, map[string]interface{}{
		"publicClientID": publicClientID,
		"json":           jsonString,
	}, "Unable to find client ID '"+publicClientID+"' among available IDs: "+jsonString)
	return "", errors.NewInternalError("Unable to find keycloak client ID")
}

// CreatePolicy creates a Keycloak policy
func CreatePolicy(ctx context.Context, clientsEndpoint string, clientID string, policy KeycloakPolicy, protectionAPIToken string) (string, error) {
	b, err := json.Marshal(policy)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"policy": policy,
			"err":    err.Error(),
		}, "Unable to marshal keyclaok policy struct")
		return "", errors.NewInternalError("unable to marshal keyclaok policy struct " + err.Error())
	}

	req, err := http.NewRequest("POST", clientsEndpoint+"/"+clientID+"/authz/resource-server/policy", strings.NewReader(string(b)))
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to crete http request")
		return "", errors.NewInternalError("unable to crete http request " + err.Error())
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+protectionAPIToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"clientID": clientID,
			"policy":   policy,
			"err":      err.Error(),
		}, "Unable to crete the Keycloak policy")
		return "", errors.NewInternalError("Unable to create the Keycloak policy " + err.Error())
	}
	if res.StatusCode != 201 {
		log.Error(ctx, map[string]interface{}{
			"clientID":       clientID,
			"policy":         policy,
			"responceStatus": res.Status,
			"responceBody":   rest.ReadBody(res.Body),
		}, "Unable to update the Keycloak policy")
		return "", errors.NewInternalError("Unable to create the Keycloak policy. Response status: " + res.Status + ". Responce body: " + rest.ReadBody(res.Body))
	}
	jsonString := rest.ReadBody(res.Body)

	var r cretePolicyRequestResultPayload
	err = json.Unmarshal([]byte(jsonString), &r)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"clientID":   clientID,
			"policy":     policy,
			"jsonString": jsonString,
		}, "Unable to unmarshal json with the create keycloak policy request result")
		return "", errors.NewInternalError(fmt.Sprintf("error when unmarshal json with the create keycloak policy request result %s ", jsonString) + err.Error())
	}

	return r.ID, nil
}

// CreatePermission creates a Keycloak permission
func CreatePermission(ctx context.Context, clientsEndpoint string, clientID string, permission KeycloakPermission, protectionAPIToken string) (string, error) {
	b, err := json.Marshal(permission)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"permission": permission,
			"err":        err.Error(),
		}, "Unable to marshal keyclaok permission struct")
		return "", errors.NewInternalError("unable to marshal keyclaok permission struct " + err.Error())
	}

	req, err := http.NewRequest("POST", clientsEndpoint+"/"+clientID+"/authz/resource-server/policy", strings.NewReader(string(b)))
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to crete http request")
		return "", errors.NewInternalError("unable to crete http request " + err.Error())
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+protectionAPIToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"clientID":   clientID,
			"permission": permission,
			"err":        err.Error(),
		}, "Unable to crete the Keycloak permission")
		return "", errors.NewInternalError("Unable to create the Keycloak permission " + err.Error())
	}
	if res.StatusCode != 201 {
		log.Error(ctx, map[string]interface{}{
			"clientID":       clientID,
			"permission":     permission,
			"responceStatus": res.Status,
			"responceBody":   rest.ReadBody(res.Body),
		}, "Unable to update the Keycloak permission")
		return "", errors.NewInternalError("Unable to create the Keycloak permission. Response status: " + res.Status + ". Responce body: " + rest.ReadBody(res.Body))
	}
	jsonString := rest.ReadBody(res.Body)

	var r cretePolicyRequestResultPayload
	err = json.Unmarshal([]byte(jsonString), &r)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"clientID":   clientID,
			"permission": permission,
			"jsonString": jsonString,
		}, "Unable to unmarshal json with the create keycloak permission request result")
		return "", errors.NewInternalError(fmt.Sprintf("error when unmarshal json with the create keycloak permission request result %s ", jsonString) + err.Error())
	}

	return r.ID, nil
}

// DeleteResource deletes the Keycloak resource assosiated with the space
func DeleteResource(ctx context.Context, kcResourceID string, authzEndpoint string, protectionAPIToken string) error {
	log.Debug(ctx, map[string]interface{}{
		"kcResourceID": kcResourceID,
	}, "Deleting the Keycloak resource")

	req, err := http.NewRequest("DELETE", authzEndpoint+"/"+kcResourceID, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to crete http request")
		return errors.NewInternalError("unable to crete http request " + err.Error())
	}
	req.Header.Add("Authorization", "Bearer "+protectionAPIToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"kcResourceID": kcResourceID,
			"err":          err.Error(),
		}, "Unable to delete the Keycloak resource")
		return errors.NewInternalError("Unable to delete the Keycloak resource " + err.Error())
	}
	if res.StatusCode != 204 {
		log.Error(ctx, map[string]interface{}{
			"kcResourceID":   kcResourceID,
			"responceStatus": res.Status,
			"responceBody":   rest.ReadBody(res.Body),
		}, "Unable to delete the Keycloak resource")
		return errors.NewInternalError("Unable to delete the Keycloak resource. Response status: " + res.Status + ". Responce body: " + rest.ReadBody(res.Body))
	}

	log.Debug(ctx, map[string]interface{}{
		"kcResourceID": kcResourceID,
	}, "Keycloak resource deleted")

	return nil
}

// DeletePolicy deletes the Keycloak policy
func DeletePolicy(ctx context.Context, clientsEndpoint string, clientID string, policyID string, protectionAPIToken string) error {
	req, err := http.NewRequest("DELETE", clientsEndpoint+"/"+clientID+"/authz/resource-server/policy/"+policyID, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to crete http request")
		return errors.NewInternalError("unable to crete http request " + err.Error())
	}
	req.Header.Add("Authorization", "Bearer "+protectionAPIToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"policyID": policyID,
			"err":      err.Error(),
		}, "Unable to delete the Keycloak policy")
		return errors.NewInternalError("Unable to delete the Keycloak policy " + err.Error())
	}
	if res.StatusCode != 204 {
		log.Error(ctx, map[string]interface{}{
			"policyID":       policyID,
			"responceStatus": res.Status,
			"responceBody":   rest.ReadBody(res.Body),
		}, "Unable to delete the Keycloak policy")
		return errors.NewInternalError("Unable to delete the Keycloak policy. Response status: " + res.Status + ". Responce body: " + rest.ReadBody(res.Body))
	}

	log.Debug(ctx, map[string]interface{}{
		"policyID": policyID,
	}, "Keycloak policy deleted")

	return nil
}

// DeletePermission deletes the Keycloak permission
func DeletePermission(ctx context.Context, clientsEndpoint string, clientID string, permissionID string, protectionAPIToken string) error {
	req, err := http.NewRequest("DELETE", clientsEndpoint+"/"+clientID+"/authz/resource-server/policy/"+permissionID, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to crete http request")
		return errors.NewInternalError("unable to crete http request " + err.Error())
	}
	req.Header.Add("Authorization", "Bearer "+protectionAPIToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"permissionID": permissionID,
			"err":          err.Error(),
		}, "Unable to delete the Keycloak permission")
		return errors.NewInternalError("Unable to delete the Keycloak permission " + err.Error())
	}
	if res.StatusCode != 204 {
		log.Error(ctx, map[string]interface{}{
			"permissionID":   permissionID,
			"responceStatus": res.Status,
			"responceBody":   rest.ReadBody(res.Body),
		}, "Unable to delete the Keycloak permission")
		return errors.NewInternalError("Unable to delete the Keycloak permission. Response status: " + res.Status + ". Responce body: " + rest.ReadBody(res.Body))
	}

	log.Debug(ctx, map[string]interface{}{
		"permissionID": permissionID,
	}, "Keycloak permission deleted")

	return nil
}

// GetPolicy obtains a policy from Keycloak
func GetPolicy(ctx context.Context, clientsEndpoint string, clientID string, policyID string, protectionAPIToken string) (*KeycloakPolicy, error) {
	req, err := http.NewRequest("GET", clientsEndpoint+"/"+clientID+"/authz/resource-server/policy/"+policyID, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to crete http request")
		return nil, errors.NewInternalError("unable to crete http request " + err.Error())
	}
	req.Header.Add("Authorization", "Bearer "+protectionAPIToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"clientID": clientID,
			"policyID": policyID,
			"err":      err.Error(),
		}, "Unable to obtain a Keycloak policy")
		return nil, errors.NewInternalError("Unable to obtain a Keycloak policy " + err.Error())
	}
	switch res.StatusCode {
	case 200:
		// OK
	case 404:
		log.Error(ctx, map[string]interface{}{
			"clientID": clientID,
			"policyID": policyID,
		}, "Keycloak policy is not found")
		return nil, errors.NewNotFoundError("policy", policyID)
	default:
		log.Error(ctx, map[string]interface{}{
			"clientID":       clientID,
			"policyID":       policyID,
			"responceStatus": res.Status,
			"responceBody":   rest.ReadBody(res.Body),
		}, "Unable to obtain a Keycloak policy")
		return nil, errors.NewInternalError("Unable to obtain a Keycloak policy. Response status: " + res.Status + ". Responce body: " + rest.ReadBody(res.Body))
	}
	jsonString := rest.ReadBody(res.Body)

	var r KeycloakPolicy
	err = json.Unmarshal([]byte(jsonString), &r)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"clientID":   clientID,
			"policyID":   policyID,
			"jsonString": jsonString,
		}, "Unable to unmarshal json with the get keycloak policy request result")
		return nil, errors.NewInternalError(fmt.Sprintf("error when unmarshal json with get the keycloak policy request result %s ", jsonString) + err.Error())
	}

	return &r, nil
}

// UpdatePolicy updates the Keycloak policy
func UpdatePolicy(ctx context.Context, clientsEndpoint string, clientID string, policy KeycloakPolicy, protectionAPIToken string) error {
	b, err := json.Marshal(policy)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"policy": policy,
			"err":    err.Error(),
		}, "Unable to marshal keyclaok policy struct")
		return errors.NewInternalError("unable to marshal keyclaok policy struct " + err.Error())
	}

	req, err := http.NewRequest("PUT", clientsEndpoint+"/"+clientID+"/authz/resource-server/policy/"+*policy.ID, strings.NewReader(string(b)))
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to crete http request")
		return errors.NewInternalError("unable to crete http request " + err.Error())
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+protectionAPIToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"clientID": clientID,
			"policy":   policy,
			"err":      err.Error(),
		}, "Unable to update the Keycloak policy")
		return errors.NewInternalError("unable to update the Keycloak policy " + err.Error())
	}
	if res.StatusCode != 201 {
		log.Error(ctx, map[string]interface{}{
			"clientID":       clientID,
			"policy":         policy,
			"responceStatus": res.Status,
			"responceBody":   rest.ReadBody(res.Body),
		}, "Unable to update the Keycloak policy")
		return errors.NewInternalError("unable to update the Keycloak policy. Response status: " + res.Status + ". Responce body: " + rest.ReadBody(res.Body))
	}

	return nil
}

// GetEntitlement obtains Entitlement for specific resource
func GetEntitlement(ctx context.Context, entitlementEndpoint string, entitlementResource EntitlementResource, userAccesToken string) (string, error) {
	b, err := json.Marshal(entitlementResource)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"entitlementResource": entitlementResource,
			"err": err.Error(),
		}, "Unable to marshal keyclaok entitlement resource struct")
		return "", errors.NewInternalError("Unable to marshal keyclaok entitlement resource struct " + err.Error())
	}

	req, err := http.NewRequest("POST", entitlementEndpoint, strings.NewReader(string(b)))
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to crete http request")
		return "", errors.NewInternalError("unable to crete http request " + err.Error())
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+userAccesToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"entitlementResource": entitlementResource,
			"err": err.Error(),
		}, "Unable to obtain entitlement resource")
		return "", errors.NewInternalError("unable to obtain entitlement resource " + err.Error())
	}
	switch res.StatusCode {
	case 200:
		// OK
	case 403:
		return "", errors.NewUnauthorizedError("not authorized")
	default:
		log.Error(ctx, map[string]interface{}{
			"entitlementResource": entitlementResource,
			"responceStatus":      res.Status,
			"responceBody":        rest.ReadBody(res.Body),
		}, "Unable to update the Keycloak permission")
		return "", errors.NewInternalError("unable to obtain entitlement resource. Response status: " + res.Status + ". Responce body: " + rest.ReadBody(res.Body))
	}
	jsonString := rest.ReadBody(res.Body)

	var r entitlementResult
	err = json.Unmarshal([]byte(jsonString), &r)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"entitlementResource": entitlementResource,
			"jsonString":          jsonString,
		}, "Unable to unmarshal json with the obtain entitlement request result")
		return "", errors.NewInternalError(fmt.Sprintf("error when unmarshal json with the obtain entitlement request result %s ", jsonString) + err.Error())
	}

	return r.Rpt, nil
}

// GetUserInfo gets user info from Keycloak
func GetUserInfo(ctx context.Context, userInfoEndpoint string, userAccessToken string) (*UserInfo, error) {
	req, err := http.NewRequest("GET", userInfoEndpoint, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to crete http request")
		return nil, errors.NewInternalError("unable to crete http request " + err.Error())
	}
	req.Header.Add("Authorization", "Bearer "+userAccessToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to get user info from Keycloak")
		return nil, errors.NewInternalError("Unable to get user info from Keycloak " + err.Error())
	}
	if res.StatusCode != 200 {
		log.Error(ctx, map[string]interface{}{}, "Unable to get user info from Keycloak")
		return nil, errors.NewInternalError("Unable to get user info from Keycloak. Response status: " + res.Status + ". Responce body: " + rest.ReadBody(res.Body))
	}
	jsonString := rest.ReadBody(res.Body)

	var r UserInfo
	err = json.Unmarshal([]byte(jsonString), &r)
	if err != nil {
		return nil, errors.NewInternalError(fmt.Sprintf("error when unmarshal json with user info payload: \"%s\" ", jsonString) + err.Error())
	}

	return &r, nil
}

// ValidateKeycloakUser returns true if the user exists in Keyclaok. Returns false if the user is not found
func ValidateKeycloakUser(ctx context.Context, adminEndpoint string, userID, protectionAPIToken string) (bool, error) {
	req, err := http.NewRequest("GET", adminEndpoint+"/users/"+userID, nil)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err": err.Error(),
		}, "Unable to crete http request")
		return false, errors.NewInternalError("unable to crete http request " + err.Error())
	}
	req.Header.Add("Authorization", "Bearer "+protectionAPIToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"userID": userID,
			"err":    err.Error(),
		}, "Unable to get user from Keycloak")
		return false, errors.NewInternalError("Unable to get user from Keycloak " + err.Error())
	}
	switch res.StatusCode {
	case 200:
		return true, nil
	case 404:
		return false, nil
	default:
		log.Error(ctx, map[string]interface{}{
			"userID": userID,
		}, "Unable to get user from Keycloak")
		return false, errors.NewInternalError("Unable to get user from Keycloak. Response status: " + res.Status + ". Responce body: " + rest.ReadBody(res.Body))
	}
}

// GetProtectedAPIToken obtains a Protected API Token (PAT) from Keycloak
func GetProtectedAPIToken(openidConnectTokenURL string, clientID string, clientSecret string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.PostForm(openidConnectTokenURL, url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"client_credentials"},
	})
	if err != nil {
		return "", errors.NewInternalError("Error when obtaining token " + err.Error())
	}
	switch res.StatusCode {
	case 200:
		// OK
	case 401:
		return "", errors.NewUnauthorizedError(res.Status + " " + rest.ReadBody(res.Body))
	case 400:
		return "", errors.NewBadParameterError(rest.ReadBody(res.Body), nil)
	default:
		return "", errors.NewInternalError(res.Status + " " + rest.ReadBody(res.Body))
	}

	token, err := ReadToken(res)
	if err != nil {
		return "", err
	}
	return *token.AccessToken, nil
}

// ReadToken extracts json with token data from the response
func ReadToken(res *http.Response) (*app.TokenData, error) {
	// Read the json out of the response body
	buf := new(bytes.Buffer)
	io.Copy(buf, res.Body)
	res.Body.Close()
	jsonString := strings.TrimSpace(buf.String())

	var token app.TokenData
	err := json.Unmarshal([]byte(jsonString), &token)
	if err != nil {
		return nil, errors.NewInternalError(fmt.Sprintf("error when unmarshal json with access token %s ", jsonString) + err.Error())
	}
	return &token, nil
}
