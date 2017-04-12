package authz_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/almighty/almighty-core/account"
	"github.com/almighty/almighty-core/application"
	"github.com/almighty/almighty-core/area"
	"github.com/almighty/almighty-core/auth"
	"github.com/almighty/almighty-core/codebase"
	"github.com/almighty/almighty-core/comment"
	config "github.com/almighty/almighty-core/configuration"
	"github.com/almighty/almighty-core/iteration"
	"github.com/almighty/almighty-core/resource"
	"github.com/almighty/almighty-core/space"
	"github.com/almighty/almighty-core/space/authz"
	authtest "github.com/almighty/almighty-core/test/auth"
	"github.com/almighty/almighty-core/workitem"
	"github.com/almighty/almighty-core/workitem/link"
	"github.com/goadesign/goa"
	"github.com/satori/go.uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	netcontext "golang.org/x/net/context"
)

var (
	scopes = []string{"read:test", "admin:test"}
)

func TestAuthz(t *testing.T) {
	resource.Require(t, resource.Remote)
	suite.Run(t, new(TestAuthzSuite))
}

type TestAuthzSuite struct {
	suite.Suite
	configuration       *config.ConfigurationData
	authzService        *authz.KeyclaokAuthzService
	entitlementEndpoint string
}

func (s *TestAuthzSuite) SetupSuite() {
	var err error
	s.configuration, err = config.GetConfigurationData()
	if err != nil {
		panic(fmt.Errorf("Failed to setup the configuration: %s", err.Error()))
	}
	var resource *space.Resource
	s.authzService = authz.NewAuthzService(s.configuration, &db{app{resource: resource}})
	r := &goa.RequestData{
		Request: &http.Request{Host: "domain.io"},
	}
	s.entitlementEndpoint, err = s.configuration.GetKeycloakEndpointEntitlement(r)
	require.Nil(s.T(), err)
}

func (s *TestAuthzSuite) TearDownSuite() {
	authtest.CleanKeycloakResources(s.T(), s.configuration)
}

func (s *TestAuthzSuite) TestFailsIfNoTokenInContext() {
	ctx := context.Background()
	spaceID := ""
	_, err := s.authzService.Authorize(ctx, s.entitlementEndpoint, spaceID)
	require.NotNil(s.T(), err)
}

type app struct {
	resource *space.Resource
}

type db struct {
	app
}

type trx struct {
	app
}

type resourceRepo struct {
	resource *space.Resource
}

func (t *trx) Commit() error {
	return nil
}

func (t *trx) Rollback() error {
	return nil
}

func (d *db) BeginTransaction() (application.Transaction, error) {
	return &trx{}, nil
}

func (a *app) WorkItems() workitem.WorkItemRepository {
	return nil
}

func (a *app) WorkItemTypes() workitem.WorkItemTypeRepository {
	return nil
}

func (a *app) Trackers() application.TrackerRepository {
	return nil
}

func (a *app) TrackerQueries() application.TrackerQueryRepository {
	return nil
}

func (a *app) SearchItems() application.SearchRepository {
	return nil
}

func (a *app) Identities() account.IdentityRepository {
	return nil
}

func (a *app) WorkItemLinkCategories() link.WorkItemLinkCategoryRepository {
	return nil
}

func (a *app) WorkItemLinkTypes() link.WorkItemLinkTypeRepository {
	return nil
}

func (a *app) WorkItemLinks() link.WorkItemLinkRepository {
	return nil
}

func (a *app) Comments() comment.Repository {
	return nil
}

func (a *app) Spaces() space.Repository {
	return nil
}

func (a *app) SpaceResources() space.ResourceRepository {
	return &resourceRepo{a.resource}
}

func (a *app) Iterations() iteration.Repository {
	return nil
}

func (a *app) Users() account.UserRepository {
	return nil
}

func (a *app) Areas() area.Repository {
	return nil
}

func (a *app) OauthStates() auth.OauthStateReferenceRepository {
	return nil
}

func (a *app) Codebases() codebase.Repository {
	return nil
}

func (r *resourceRepo) Create(ctx netcontext.Context, s *space.Resource) (*space.Resource, error) {
	return nil, nil
}

func (r *resourceRepo) Save(ctx netcontext.Context, s *space.Resource) (*space.Resource, error) {
	return nil, nil
}

func (r *resourceRepo) Load(ctx netcontext.Context, ID uuid.UUID) (*space.Resource, error) {
	return nil, nil
}

func (r *resourceRepo) Delete(ctx netcontext.Context, ID uuid.UUID) error {
	return nil
}

func (r *resourceRepo) LoadBySpace(ctx netcontext.Context, spaceID *uuid.UUID) (*space.Resource, error) {
	return r.resource, nil
}
