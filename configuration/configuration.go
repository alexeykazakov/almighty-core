package configuration

import (
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v2"

	"github.com/almighty/almighty-core/rest"
	"github.com/goadesign/goa"
	"github.com/spf13/viper"
)

// String returns the current configuration as a string
func (c *ConfigurationData) String() string {
	allSettings := c.v.AllSettings()
	y, err := yaml.Marshal(&allSettings)
	if err != nil {
		log.WithFields(map[string]interface{}{
			"settings": allSettings,
			"err":      err,
		}).Panicln("Failed to marshall config to string")
	}
	return fmt.Sprintf("%s\n", y)
}

const (
	// Constants for viper variable names. Will be used to set
	// default values as well as to get each value

	varPostgresHost                     = "postgres.host"
	varPostgresPort                     = "postgres.port"
	varPostgresUser                     = "postgres.user"
	varPostgresDatabase                 = "postgres.database"
	varPostgresPassword                 = "postgres.password"
	varPostgresSSLMode                  = "postgres.sslmode"
	varPostgresConnectionTimeout        = "postgres.connection.timeout"
	varPostgresConnectionRetrySleep     = "postgres.connection.retrysleep"
	varPostgresConnectionMaxIdle        = "postgres.connection.maxidle"
	varPostgresConnectionMaxOpen        = "postgres.connection.maxopen"
	varPopulateCommonTypes              = "populate.commontypes"
	varHTTPAddress                      = "http.address"
	varDeveloperModeEnabled             = "developer.mode.enabled"
	varGithubAuthToken                  = "github.auth.token"
	varKeycloakSecret                   = "keycloak.secret"
	varKeycloakClientID                 = "keycloak.client.id"
	varKeycloakDomainPrefix             = "keycloak.domain.prefix"
	varKeycloakRealm                    = "keycloak.realm"
	varKeycloakTesUserName              = "keycloak.testuser.name"
	varKeycloakTesUserSecret            = "keycloak.testuser.secret"
	varKeycloakTesUser2Name             = "keycloak.testuser2.name"
	varKeycloakTesUser2Secret           = "keycloak.testuser2.secret"
	varKeycloakURL                      = "keycloak.url"
	varKeycloakEndpointAdmin            = "keycloak.endpoint.admin"
	varKeycloakEndpointAuth             = "keycloak.endpoint.auth"
	varKeycloakEndpointToken            = "keycloak.endpoint.token"
	varKeycloakEndpointUserinfo         = "keycloak.endpoint.userinfo"
	varKeycloakEndpointAuthzResourceset = "keycloak.endpoint.authz.resourceset"
	varKeycloakEndpointClients          = "keycloak.endpoint.clients"
	varKeycloakEndpointEntitlement      = "keycloak.endpoint.entitlement"
	varKeycloakEndpointBroker           = "keycloak.endpoint.broker"
	varTokenPublicKey                   = "token.publickey"
	varTokenPrivateKey                  = "token.privatekey"
	varCacheControlWorkItemType         = "cachecontrol.workitemtype"
	varCacheControlWorkItemLinkType     = "cachecontrol.workitemlinktype"
	defaultConfigFile                   = "config.yaml"
)

// ConfigurationData encapsulates the Viper configuration object which stores the configuration data in-memory.
type ConfigurationData struct {
	v *viper.Viper
}

// NewConfigurationData creates a configuration reader object using a configurable configuration file path
func NewConfigurationData(configFilePath string) (*ConfigurationData, error) {
	c := ConfigurationData{
		v: viper.New(),
	}
	c.v.SetEnvPrefix("ALMIGHTY")
	c.v.AutomaticEnv()
	c.v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	c.v.SetTypeByDefaultValue(true)
	c.setConfigDefaults()

	if configFilePath != "" {
		c.v.SetConfigType("yaml")
		c.v.SetConfigFile(configFilePath)
		err := c.v.ReadInConfig() // Find and read the config file
		if err != nil {           // Handle errors reading the config file
			return nil, errors.Errorf("Fatal error config file: %s \n", err)
		}
	}
	return &c, nil
}

func getConfigFilePath() string {
	// This was either passed as a env var Or, set inside main.go from --config
	envConfigPath, ok := os.LookupEnv("ALMIGHTY_CONFIG_FILE_PATH")
	if !ok {
		return ""
	}
	return envConfigPath
}

// GetDefaultConfigurationFile returns the default configuration file.
func (c *ConfigurationData) GetDefaultConfigurationFile() string {
	return defaultConfigFile
}

// GetConfigurationData is a wrapper over NewConfigurationData which reads configuration file path
// from the environment variable.
func GetConfigurationData() (*ConfigurationData, error) {
	cd, err := NewConfigurationData(getConfigFilePath())
	return cd, err
}

func (c *ConfigurationData) setConfigDefaults() {
	//---------
	// Postgres
	//---------
	c.v.SetTypeByDefaultValue(true)
	c.v.SetDefault(varPostgresHost, "localhost")
	c.v.SetDefault(varPostgresPort, 5432)
	c.v.SetDefault(varPostgresUser, "postgres")
	c.v.SetDefault(varPostgresDatabase, "postgres")
	c.v.SetDefault(varPostgresPassword, "mysecretpassword")
	c.v.SetDefault(varPostgresSSLMode, "disable")
	c.v.SetDefault(varPostgresConnectionTimeout, 5)
	c.v.SetDefault(varPostgresConnectionMaxIdle, -1)
	c.v.SetDefault(varPostgresConnectionMaxOpen, -1)

	// Number of seconds to wait before trying to connect again
	c.v.SetDefault(varPostgresConnectionRetrySleep, time.Duration(time.Second))

	//-----
	// HTTP
	//-----
	c.v.SetDefault(varHTTPAddress, "0.0.0.0:8080")

	//-----
	// Misc
	//-----

	// Enable development related features, e.g. token generation endpoint
	c.v.SetDefault(varDeveloperModeEnabled, false)

	c.v.SetDefault(varPopulateCommonTypes, true)

	// Auth-related defaults
	c.v.SetDefault(varTokenPublicKey, defaultTokenPublicKey)
	c.v.SetDefault(varTokenPrivateKey, defaultTokenPrivateKey)
	c.v.SetDefault(varKeycloakClientID, defaultKeycloakClientID)
	c.v.SetDefault(varKeycloakSecret, defaultKeycloakSecret)
	c.v.SetDefault(varGithubAuthToken, defaultActualToken)
	c.v.SetDefault(varKeycloakDomainPrefix, defaultKeycloakDomainPrefix)
	c.v.SetDefault(varKeycloakTesUserName, defaultKeycloakTesUserName)
	c.v.SetDefault(varKeycloakTesUserSecret, defaultKeycloakTesUserSecret)

	// HTTP Cache-Control/max-age default
	c.v.SetDefault(varCacheControlWorkItemType, "max-age=86400")     // 1 day
	c.v.SetDefault(varCacheControlWorkItemLinkType, "max-age=86400") // 1 day

	c.v.SetDefault(varKeycloakTesUser2Name, defaultKeycloakTesUser2Name)
	c.v.SetDefault(varKeycloakTesUser2Secret, defaultKeycloakTesUser2Secret)
}

// GetPostgresHost returns the postgres host as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresHost() string {
	return c.v.GetString(varPostgresHost)
}

// GetPostgresPort returns the postgres port as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresPort() int64 {
	return c.v.GetInt64(varPostgresPort)
}

// GetPostgresUser returns the postgres user as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresUser() string {
	return c.v.GetString(varPostgresUser)
}

// GetPostgresDatabase returns the postgres database as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresDatabase() string {
	return c.v.GetString(varPostgresDatabase)
}

// GetPostgresPassword returns the postgres password as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresPassword() string {
	return c.v.GetString(varPostgresPassword)
}

// GetPostgresSSLMode returns the postgres sslmode as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresSSLMode() string {
	return c.v.GetString(varPostgresSSLMode)
}

// GetPostgresConnectionTimeout returns the postgres connection timeout as set via default, config file, or environment variable
func (c *ConfigurationData) GetPostgresConnectionTimeout() int64 {
	return c.v.GetInt64(varPostgresConnectionTimeout)
}

// GetPostgresConnectionRetrySleep returns the number of seconds (as set via default, config file, or environment variable)
// to wait before trying to connect again
func (c *ConfigurationData) GetPostgresConnectionRetrySleep() time.Duration {
	return c.v.GetDuration(varPostgresConnectionRetrySleep)
}

// GetPostgresConnectionMaxIdle returns the number of connections that should be keept alive in the database connection pool at
// any given time. -1 represents no restrictions/default behavior
func (c *ConfigurationData) GetPostgresConnectionMaxIdle() int {
	return c.v.GetInt(varPostgresConnectionMaxIdle)
}

// GetPostgresConnectionMaxOpen returns the max number of open connections that should be open in the database connection pool.
// -1 represents no restrictions/default behavior
func (c *ConfigurationData) GetPostgresConnectionMaxOpen() int {
	return c.v.GetInt(varPostgresConnectionMaxOpen)
}

// GetPostgresConfigString returns a ready to use string for usage in sql.Open()
func (c *ConfigurationData) GetPostgresConfigString() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d",
		c.GetPostgresHost(),
		c.GetPostgresPort(),
		c.GetPostgresUser(),
		c.GetPostgresPassword(),
		c.GetPostgresDatabase(),
		c.GetPostgresSSLMode(),
		c.GetPostgresConnectionTimeout(),
	)
}

// GetPopulateCommonTypes returns true if the (as set via default, config file, or environment variable)
// the common work item types such as bug or feature shall be created.
func (c *ConfigurationData) GetPopulateCommonTypes() bool {
	return c.v.GetBool(varPopulateCommonTypes)
}

// GetHTTPAddress returns the HTTP address (as set via default, config file, or environment variable)
// that the alm server binds to (e.g. "0.0.0.0:8080")
func (c *ConfigurationData) GetHTTPAddress() string {
	return c.v.GetString(varHTTPAddress)
}

// IsPostgresDeveloperModeEnabled returns if development related features (as set via default, config file, or environment variable),
// e.g. token generation endpoint are enabled
func (c *ConfigurationData) IsPostgresDeveloperModeEnabled() bool {
	return c.v.GetBool(varDeveloperModeEnabled)
}

// GetCacheControlWorkItemType returns the value to set in the "Cache-Control: max-age=%v" HTTP response header
// when returning a work item type (or a list of).
func (c *ConfigurationData) GetCacheControlWorkItemType() string {
	return c.v.GetString(varCacheControlWorkItemType)
}

// GetCacheControlWorkItemLinkType returns the value to set in the "Cache-Control: max-age=%v" HTTP response header
// when returning a work item type (or a list of).
func (c *ConfigurationData) GetCacheControlWorkItemLinkType() string {
	return c.v.GetString(varCacheControlWorkItemLinkType)
}

// GetTokenPrivateKey returns the private key (as set via config file or environment variable)
// that is used to sign the authentication token.
func (c *ConfigurationData) GetTokenPrivateKey() []byte {
	return []byte(c.v.GetString(varTokenPrivateKey))
}

// GetTokenPublicKey returns the public key (as set via config file or environment variable)
// that is used to decrypt the authentication token.
func (c *ConfigurationData) GetTokenPublicKey() []byte {
	return []byte(c.v.GetString(varTokenPublicKey))
}

// GetGithubAuthToken returns the actual Github OAuth Access Token
func (c *ConfigurationData) GetGithubAuthToken() string {
	return c.v.GetString(varGithubAuthToken)
}

// GetKeycloakSecret returns the keycloak client secret (as set via config file or environment variable)
// that is used to make authorized Keycloak API Calls.
func (c *ConfigurationData) GetKeycloakSecret() string {
	return c.v.GetString(varKeycloakSecret)
}

// GetKeycloakClientID returns the keycloak client ID (as set via config file or environment variable)
// that is used to make authorized Keycloak API Calls.
func (c *ConfigurationData) GetKeycloakClientID() string {
	return c.v.GetString(varKeycloakClientID)
}

// GetKeycloakDomainPrefix returns the domain prefix which should be used in all Keycloak requests
func (c *ConfigurationData) GetKeycloakDomainPrefix() string {
	return c.v.GetString(varKeycloakDomainPrefix)
}

// GetKeycloakRealm returns the keyclaok realm name
func (c *ConfigurationData) GetKeycloakRealm() string {
	if c.v.IsSet(varKeycloakRealm) {
		return c.v.GetString(varKeycloakRealm)
	}
	if c.IsPostgresDeveloperModeEnabled() {
		return devModeKeycloakRealm
	}
	return defaultKeycloakRealm
}

// GetKeycloakTestUserName returns the keycloak test user name used to obtain a test token (as set via config file or environment variable)
func (c *ConfigurationData) GetKeycloakTestUserName() string {
	return c.v.GetString(varKeycloakTesUserName)
}

// GetKeycloakTestUserSecret returns the keycloak test user password used to obtain a test token (as set via config file or environment variable)
func (c *ConfigurationData) GetKeycloakTestUserSecret() string {
	return c.v.GetString(varKeycloakTesUserSecret)
}

// GetKeycloakTestUser2Name returns the keycloak test user name used to obtain a test token (as set via config file or environment variable)
func (c *ConfigurationData) GetKeycloakTestUser2Name() string {
	return c.v.GetString(varKeycloakTesUser2Name)
}

// GetKeycloakTestUser2Secret returns the keycloak test user password used to obtain a test token (as set via config file or environment variable)
func (c *ConfigurationData) GetKeycloakTestUser2Secret() string {
	return c.v.GetString(varKeycloakTesUser2Secret)
}

// GetKeycloakEndpointAuth returns the keycloak auth endpoint set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointAuth(req *goa.RequestData) (string, error) {
	return c.getKeycloakOpenIDConnectEndpoint(req, varKeycloakEndpointAuth, "auth")
}

// GetKeycloakEndpointToken returns the keycloak token endpoint set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointToken(req *goa.RequestData) (string, error) {
	return c.getKeycloakOpenIDConnectEndpoint(req, varKeycloakEndpointToken, "token")
}

// GetKeycloakEndpointUserInfo returns the keycloak userinfo endpoint set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointUserInfo(req *goa.RequestData) (string, error) {
	return c.getKeycloakOpenIDConnectEndpoint(req, varKeycloakEndpointUserinfo, "userinfo")
}

// GetKeycloakEndpointAdmin returns the <keyclaok>/realms/admin/<realm> endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointAdmin(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointAdmin, "auth/admin/realms/"+c.GetKeycloakRealm())
}

// GetKeycloakEndpointAuthzResourceset returns the <keyclaok>/realms/<realm>/authz/protection/resource_set endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointAuthzResourceset(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointAuthzResourceset, "auth/realms/"+c.GetKeycloakRealm()+"/authz/protection/resource_set")
}

// GetKeycloakEndpointClients returns the <keyclaok>/admin/realms/<realm>/clients endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointClients(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointClients, "auth/admin/realms/"+c.GetKeycloakRealm()+"/clients")
}

// GetKeycloakEndpointEntitlement returns the <keyclaok>/realms/<realm>/authz/entitlement/<clientID> endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointEntitlement(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointEntitlement, "auth/realms/"+c.GetKeycloakRealm()+"/authz/entitlement/"+c.GetKeycloakClientID())
}

// GetKeycloakEndpointBroker returns the <keyclaok>/realms/<realm>/authz/entitlement/<clientID> endpoint
// set via config file or environment variable.
// If nothing set then in Dev environment the defualt endopoint will be returned.
// In producion the endpoint will be calculated from the request by replacing the last domain/host name in the full host name.
// Example: api.service.domain.org -> sso.service.domain.org
// or api.domain.org -> sso.domain.org
func (c *ConfigurationData) GetKeycloakEndpointBroker(req *goa.RequestData) (string, error) {
	return c.getKeycloakEndpoint(req, varKeycloakEndpointBroker, "auth/realms/"+c.GetKeycloakRealm()+"/broker")
}

// GetKeycloakDevModeURL returns Keycloak URL used by default in Dev mode
func (c *ConfigurationData) GetKeycloakDevModeURL() string {
	return devModeKeycloakURL
}

func (c *ConfigurationData) getKeycloakOpenIDConnectEndpoint(req *goa.RequestData, endpointVarName string, pathSufix string) (string, error) {
	return c.getKeycloakEndpoint(req, endpointVarName, c.openIDConnectPath(pathSufix))
}

func (c *ConfigurationData) getKeycloakEndpoint(req *goa.RequestData, endpointVarName string, pathSufix string) (string, error) {
	if c.v.IsSet(endpointVarName) {
		return c.v.GetString(endpointVarName), nil
	}
	var endpoint string
	var err error
	if c.v.IsSet(varKeycloakURL) {
		// Keycloak URL is set. Calculate the URL endpoint
		endpoint = fmt.Sprintf("%s/%s", c.v.GetString(varKeycloakURL), pathSufix)
	} else {
		if c.IsPostgresDeveloperModeEnabled() {
			// Devmode is enabled. Calculate the URL endopoint using the devmode Keyclaok URL
			endpoint = fmt.Sprintf("%s/%s", devModeKeycloakURL, pathSufix)
		} else {
			// Calculate relative URL based on request
			endpoint, err = c.getKeycloakURL(req, pathSufix)
			if err != nil {
				return "", err
			}
		}
	}

	// Can't set this variable because viper is not thread-safe. See https://github.com/spf13/viper/issues/268
	// c.v.Set(endpointVarName, endpoint) // Set the variable, so, we don't have to recalculate it again the next time
	return endpoint, nil
}

func (c *ConfigurationData) openIDConnectPath(suffix string) string {
	return "auth/realms/" + c.GetKeycloakRealm() + "/protocol/openid-connect/" + suffix
}

func (c *ConfigurationData) getKeycloakURL(req *goa.RequestData, path string) (string, error) {
	scheme := "http"
	if req.TLS != nil { // isHTTPS
		scheme = "https"
	}
	newHost, err := rest.ReplaceDomainPrefix(req.Host, c.GetKeycloakDomainPrefix())
	if err != nil {
		return "", err
	}
	newURL := fmt.Sprintf("%s://%s/%s", scheme, newHost, path)

	return newURL, nil
}

// Auth-related defaults

// RSAPrivateKey for signing JWT Tokens
// ssh-keygen -f alm_rsa
var defaultTokenPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAnwrjH5iTSErw9xUptp6QSFoUfpHUXZ+PaslYSUrpLjw1q27O
DSFwmhV4+dAaTMO5chFv/kM36H3ZOyA146nwxBobS723okFaIkshRrf6qgtD6coT
HlVUSBTAcwKEjNn4C9jtEpyOl+eSgxhMzRH3bwTIFlLlVMiZf7XVE7P3yuOCpqkk
2rdYVSpQWQWKU+ZRywJkYcLwjEYjc70AoNpjO5QnY+Exx98E30iEdPHZpsfNhsjh
9Z7IX5TrMYgz7zBTw8+niO/uq3RBaHyIhDbvenbR9Q59d88lbnEeHKgSMe2RQpFR
3rxFRkc/64Rn/bMuL/ptNowPqh1P+9GjYzWmPwIDAQABAoIBAQCBCl5ZpnvprhRx
BVTA/Upnyd7TCxNZmzrME+10Gjmz79pD7DV25ejsu/taBYUxP6TZbliF3pggJOv6
UxomTB4znlMDUz0JgyjUpkyril7xVQ6XRAPbGrS1f1Def+54MepWAn3oGeqASb3Q
bAj0Yl12UFTf+AZmkhQpUKk/wUeN718EIY4GRHHQ6ykMSqCKvdnVbMyb9sIzbSTl
v+l1nQFnB/neyJq6P0Q7cxlhVj03IhYj/AxveNlKqZd2Ih3m/CJo0Abtwhx+qHZp
cCBrYj7VelEaGARTmfoIVoGxFGKZNCcNzn7R2ic7safxXqeEnxugsAYX/UmMoq1b
vMYLcaLRAoGBAMqMbbgejbD8Cy6wa5yg7XquqOP5gPdIYYS88TkQTp+razDqKPIU
hPKetnTDJ7PZleOLE6eJ+dQJ8gl6D/dtOsl4lVRy/BU74dk0fYMiEfiJMYEYuAU0
MCramo3HAeySTP8pxSLFYqJVhcTpL9+NQgbpJBUlx5bLDlJPl7auY077AoGBAMkD
UpJRIv/0gYSz5btVheEyDzcqzOMZUVsngabH7aoQ49VjKrfLzJ9WznzJS5gZF58P
vB7RLuIA8m8Y4FUwxOr4w9WOevzlFh0gyzgNY4gCwrzEryOZqYYqCN+8QLWfq/hL
+gYFYpEW5pJ/lAy2i8kPanC3DyoqiZCsUmlg6JKNAoGBAIdCkf6zgKGhHwKV07cs
DIqx2p0rQEFid6UB3ADkb+zWt2VZ6fAHXeT7shJ1RK0o75ydgomObWR5I8XKWqE7
s1dZjDdx9f9kFuVK1Upd1SxoycNRM4peGJB1nWJydEl8RajcRwZ6U+zeOc+OfWbH
WUFuLadlrEx5212CQ2k+OZlDAoGAdsH2w6kZ83xCFOOv41ioqx5HLQGlYLpxfVg+
2gkeWa523HglIcdPEghYIBNRDQAuG3RRYSeW+kEy+f4Jc2tHu8bS9FWkRcsWoIji
ZzBJ0G5JHPtaub6sEC6/ZWe0F1nJYP2KLop57FxKRt0G2+fxeA0ahpMwa2oMMiQM
4GM3pHUCgYEAj2ZjjsF2MXYA6kuPUG1vyY9pvj1n4fyEEoV/zxY1k56UKboVOtYr
BA/cKaLPqUF+08Tz/9MPBw51UH4GYfppA/x0ktc8998984FeIpfIFX6I2U9yUnoQ
OCCAgsB8g8yTB4qntAYyfofEoDiseKrngQT5DSdxd51A/jw7B8WyBK8=
-----END RSA PRIVATE KEY-----`

// RSAPublicKey for verifying JWT Tokens
// openssl rsa -in alm_rsa -pubout -out alm_rsa.pub
var defaultTokenPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArlscGA2NfO4ZkGzJgZE8
e/WGHCFANE28DzU1aftOssKi4jCn++umFWPDWxTwLfQdiwc8Bbhn9/8udPMXrZ84
L8OgVNbDXOle37QE0+GEAX/DnzkvOg2sm7F0IzKck9YNvo3ZUYj7dyW9s2zatCwu
QyUsHJmbMdwtDOueHBHwXiAiU0kprtUjNsvK4SBvascBdCmLLIWkhj2lu5S6BGrH
gDDTv2JaguNwlgbHLFWU08D03j2F5Yj4TO8LexRJwCYrKp1icQrvC+WGhRAlttbx
51MKRiCnqhFJ8LYtCbPt5Xm5+FR2fHFCMyCqQsScu+dwsx+mb4JGAsdVEaUdcmOF
ZwIDAQAB
-----END PUBLIC KEY-----`

var defaultKeycloakClientID = "fabric8-online-platform"
var defaultKeycloakSecret = "7a3d5a00-7f80-40cf-8781-b5b6f2dfd1bd"

var defaultKeycloakDomainPrefix = "sso"
var defaultKeycloakRealm = "fabric8"

// Github does not allow committing actual OAuth tokens no matter how less privilege the token has
var camouflagedAccessToken = "751e16a8b39c0985066-AccessToken-4871777f2c13b32be8550"

// ActualToken is actual OAuth access token of github
var defaultActualToken = strings.Split(camouflagedAccessToken, "-AccessToken-")[0] + strings.Split(camouflagedAccessToken, "-AccessToken-")[1]

var defaultKeycloakTesUserName = "testuser"
var defaultKeycloakTesUserSecret = "testuser"
var defaultKeycloakTesUser2Name = "testuser2"
var defaultKeycloakTesUser2Secret = "testuser2"

// Keycloak vars to be used in dev mode. Can be overridden by setting up keycloak.url & keycloak.realm
var devModeKeycloakURL = "http://sso.prod-preview.openshift.io"
var devModeKeycloakRealm = "fabric8-test"
