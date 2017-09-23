package controller

import (
	"context"
	"encoding/json"
	er "errors"
	"net/http"
	"net/url"

	"github.com/fabric8-services/fabric8-wit/account"
	"github.com/fabric8-services/fabric8-wit/app"
	"github.com/fabric8-services/fabric8-wit/client"
	"github.com/fabric8-services/fabric8-wit/errors"
	"github.com/fabric8-services/fabric8-wit/goasupport"
	"github.com/fabric8-services/fabric8-wit/jsonapi"
	"github.com/fabric8-services/fabric8-wit/log"
	"github.com/fabric8-services/fabric8-wit/login"
	generate "github.com/fabric8-services/fabric8-wit/test/token"
	"github.com/fabric8-services/fabric8-wit/token"

	"github.com/goadesign/goa"
	goaclient "github.com/goadesign/goa/client"
	errs "github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

type loginConfiguration interface {
	IsPostgresDeveloperModeEnabled() bool
	GetKeycloakTestUserName() string
	GetKeycloakTestUser2Name() string
	GetAuthEndpointLogin(*http.Request) (string, error)
	GetAuthEndpointLink(req *http.Request) (string, error)
	GetAuthEndpointLinksession(req *http.Request) (string, error)
	GetAuthEndpointTokenRefresh(req *http.Request) (string, error)
	IsAuthorizationEnabled() bool
}

// LoginController implements the login resource.
type LoginController struct {
	*goa.Controller
	auth               login.KeycloakOAuthService
	tokenManager       token.Manager
	configuration      loginConfiguration
	identityRepository account.IdentityRepository
}

// NewLoginController creates a login controller.
func NewLoginController(service *goa.Service, auth *login.KeycloakOAuthProvider, tokenManager token.Manager, configuration loginConfiguration, identityRepository account.IdentityRepository) *LoginController {
	return &LoginController{Controller: service.NewController("login"), auth: auth, tokenManager: tokenManager, configuration: configuration, identityRepository: identityRepository}
}

// Authorize runs the authorize action.
func (c *LoginController) Authorize(ctx *app.AuthorizeLoginContext) error {
	if !c.configuration.IsAuthorizationEnabled() {
		// Login as test user
		redirect := ctx.Request.Header.Get("redirect")
		referrer := ctx.Request.Header.Get("Referer")
		if redirect == "" {
			if referrer == "" {
				return jsonapi.JSONErrorResponse(ctx, er.New("referer header and redirect param are both empty; at least one should be specified"))
			}
			redirect = referrer
		}

		cln := client.New(goaclient.HTTPClientDoer(http.DefaultClient))
		cln.Host = ctx.Request.Host
		cln.Scheme = ctx.URL.Scheme
		res, err := cln.GenerateLogin(goasupport.ForwardContextRequestID(ctx), client.GenerateLoginPath())
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
		tokens, err := cln.DecodeAuthTokenCollection(res)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
		tokenData := &app.TokenData{
			AccessToken:      tokens[0].Token.AccessToken,
			ExpiresIn:        tokens[0].Token.ExpiresIn,
			RefreshToken:     tokens[0].Token.RefreshToken,
			RefreshExpiresIn: tokens[0].Token.RefreshExpiresIn,
			NotBeforePolicy:  tokens[0].Token.NotBeforePolicy,
			TokenType:        tokens[0].Token.TokenType,
		}
		b, err := json.Marshal(tokenData)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}

		location, err := url.Parse(redirect)
		if err != nil {
			return jsonapi.JSONErrorResponse(ctx, err)
		}
		parameters := location.Query()
		parameters.Add("token_json", string(b))
		location.RawQuery = parameters.Encode()
		ctx.ResponseData.Header().Set("Location", location.String())
		return ctx.TemporaryRedirect()
	}
	authEndpoint, err := c.configuration.GetAuthEndpointLogin(ctx.Request)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	locationURL, err := redirectLocation(ctx.Params, authEndpoint)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	ctx.ResponseData.Header().Set("Location", locationURL)
	return ctx.TemporaryRedirect()
}

func redirectLocation(params url.Values, location string) (string, error) {
	locationURL, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	parameters := locationURL.Query()
	for name := range params {
		parameters.Add(name, params.Get(name))
	}
	locationURL.RawQuery = parameters.Encode()
	return locationURL.String(), nil
}

// Refresh obtain a new access token using the refresh token.
func (c *LoginController) Refresh(ctx *app.RefreshLoginContext) error {
	if !c.configuration.IsAuthorizationEnabled() {
		return jsonapi.JSONErrorResponse(ctx, er.New("token refresh endpoint disabled"))
	}
	authEndpoint, err := c.configuration.GetAuthEndpointTokenRefresh(ctx.Request)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, err)
	}
	ctx.ResponseData.Header().Set("Location", authEndpoint)
	return ctx.TemporaryRedirect()
}

// Link links identity provider(s) to the user's account
func (c *LoginController) Link(ctx *app.LinkLoginContext) error {
	authEndpoint, err := c.configuration.GetAuthEndpointLink(ctx.RequestData.Request)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	locationURL, err := redirectLocation(ctx.Params, authEndpoint)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	ctx.ResponseData.Header().Set("Location", locationURL)
	return ctx.TemporaryRedirect()
}

// Linksession links identity provider(s) to the user's account
func (c *LoginController) Linksession(ctx *app.LinksessionLoginContext) error {
	authEndpoint, err := c.configuration.GetAuthEndpointLinksession(ctx.RequestData.Request)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	locationURL, err := redirectLocation(ctx.Params, authEndpoint)
	if err != nil {
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, err))
	}
	ctx.ResponseData.Header().Set("Location", locationURL)
	return ctx.TemporaryRedirect()
}

// Generate obtain the access token from Keycloak for the test user
func (c *LoginController) Generate(ctx *app.GenerateLoginContext) error {
	var tokens app.AuthTokenCollection

	testuser, err := GenerateUserToken(ctx, c.configuration, c.configuration.GetKeycloakTestUserName())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"username": c.configuration.GetKeycloakTestUserName(),
		}, "unable to get Generate User token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to generate test token ")))
	}
	// Creates the testuser user and identity if they don't yet exist
	c.auth.CreateOrUpdateKeycloakUser(*testuser.Token.AccessToken, ctx)
	tokens = append(tokens, testuser)

	testuser, err = GenerateUserToken(ctx, c.configuration, c.configuration.GetKeycloakTestUser2Name())
	if err != nil {
		log.Error(ctx, map[string]interface{}{
			"err":      err,
			"username": c.configuration.GetKeycloakTestUser2Name(),
		}, "unable to generate test token")
		return jsonapi.JSONErrorResponse(ctx, errors.NewInternalError(ctx, errs.Wrap(err, "unable to generate test token")))
	}
	// Creates the testuser2 user and identity if they don't yet exist
	c.auth.CreateOrUpdateKeycloakUser(*testuser.Token.AccessToken, ctx)
	tokens = append(tokens, testuser)

	ctx.ResponseData.Header().Set("Cache-Control", "no-cache")
	return ctx.OK(tokens)
}

// GenerateUserToken obtains the access token from Keycloak for the user
func GenerateUserToken(ctx context.Context, configuration loginConfiguration, username string) (*app.AuthToken, error) {
	if !configuration.IsPostgresDeveloperModeEnabled() {
		log.Error(ctx, map[string]interface{}{
			"method": "Generate",
		}, "Developer mode not enabled")
		return nil, errors.NewInternalError(ctx, errs.New("postgres developer mode is not enabled"))
	}

	key := generate.PrivateKey()
	token, err := generate.GenerateToken(uuid.NewV4().String(), username, key)
	if err != nil {
		return nil, err
	}

	bearer := "Bearer"
	return &app.AuthToken{Token: &app.TokenData{
		AccessToken:      &token,
		ExpiresIn:        60 * 60 * 24 * 30,
		NotBeforePolicy:  0,
		RefreshExpiresIn: 60 * 60 * 24 * 30,
		RefreshToken:     &token,
		TokenType:        &bearer,
	}}, nil
}
