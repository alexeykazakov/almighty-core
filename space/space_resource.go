package space

import (
	"github.com/almighty/almighty-core/convert"
	"github.com/almighty/almighty-core/errors"
	"github.com/almighty/almighty-core/gormsupport"
	"github.com/almighty/almighty-core/log"

	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/net/context"
)

const (
	resourceTableName = "space_resources"
)

// Resource represents a Keycloak space resource on the domain and db layer
type Resource struct {
	gormsupport.Lifecycle
	ID           uuid.UUID `sql:"type:uuid default uuid_generate_v4()" gorm:"primary_key"`
	ResourceID   string    `gorm:"column:resource_id"`
	PermissionID string    `gorm:"column:permission_id"`
	PolicyID     string    `gorm:"column:policy_id"`
	SpaceID      uuid.UUID `sql:"type:uuid" gorm:"column:space_id"` // Belongs to Space
}

// TableName implements gorm.tabler
func (r Resource) TableName() string {
	return resourceTableName
}

// Equal returns true if two Space Resource objects are equal; otherwise false is returned.
func (r Resource) Equal(u convert.Equaler) bool {
	other, ok := u.(Resource)
	if !ok {
		return false
	}
	if r.ResourceID != other.ResourceID {
		return false
	}
	if r.PermissionID != other.PermissionID {
		return false
	}
	if r.PolicyID != other.PolicyID {
		return false
	}
	return true
}

// ResourceRepository encapsulate storage & retrieval of space resources
type ResourceRepository interface {
	Create(ctx context.Context, space *Resource) (*Resource, error)
	Save(ctx context.Context, space *Resource) (*Resource, error)
	Load(ctx context.Context, ID uuid.UUID) (*Resource, error)
	Delete(ctx context.Context, ID uuid.UUID) error
	LoadBySpace(ctx context.Context, spaceID *uuid.UUID) (*Resource, error)
}

// NewResourceRepository creates a new space resource repo
func NewResourceRepository(db *gorm.DB) *GormResourceRepository {
	return &GormResourceRepository{db}
}

// GormResourceRepository implements ResourceRepository using gorm
type GormResourceRepository struct {
	db *gorm.DB
}

// Load returns the space resource for the given id
// returns NotFoundError or InternalError
func (r *GormResourceRepository) Load(ctx context.Context, ID uuid.UUID) (*Resource, error) {
	res := Resource{}
	tx := r.db.Where("id=?", ID).First(&res)
	if tx.RecordNotFound() {
		log.Error(ctx, map[string]interface{}{
			"spaceResourceID": ID.String(),
		}, "state or known referer was empty")
		return nil, errors.NewNotFoundError("space resource", ID.String())
	}
	if tx.Error != nil {
		return nil, errors.NewInternalError(tx.Error.Error())
	}
	return &res, nil
}

// Delete deletes the space resource with the given id
// returns NotFoundError or InternalError
func (r *GormResourceRepository) Delete(ctx context.Context, ID uuid.UUID) error {
	if ID == uuid.Nil {
		log.Error(ctx, map[string]interface{}{
			"spaceResourceID": ID.String(),
		}, "unable to find the space resource by ID")
		return errors.NewNotFoundError("space resource", ID.String())
	}
	resource := Resource{ID: ID}
	tx := r.db.Delete(resource)

	if err := tx.Error; err != nil {
		log.Error(ctx, map[string]interface{}{
			"spaceResourceID": ID.String(),
		}, "unable to delete the space resource")
		return errors.NewInternalError(err.Error())
	}
	if tx.RowsAffected == 0 {
		log.Error(ctx, map[string]interface{}{
			"spaceResourceID": ID.String(),
		}, "none row was affected by the deletion operation")
		return errors.NewNotFoundError("space resource", ID.String())
	}

	return nil
}

// Save updates the given space resource in the DB
// returns NotFoundError, VersionConflictError or InternalError
func (r *GormResourceRepository) Save(ctx context.Context, p *Resource) (*Resource, error) {
	pr := Resource{}
	tx := r.db.Where("id=?", p.ID).First(&pr)
	if tx.RecordNotFound() {
		return nil, errors.NewNotFoundError("space resource", p.ID.String())
	}
	if err := tx.Error; err != nil {
		return nil, errors.NewInternalError(err.Error())
	}

	log.Info(ctx, map[string]interface{}{
		"spaceResourceID": p.ID,
	}, "Space resource updated successfully")
	return p, nil
}

// Create creates a new Space Resource in the DB
// returns InternalError
func (r *GormResourceRepository) Create(ctx context.Context, resource *Resource) (*Resource, error) {
	if resource.ID == uuid.Nil {
		resource.ID = uuid.NewV4()
	}

	tx := r.db.Create(resource)
	if err := tx.Error; err != nil {
		return nil, errors.NewInternalError(err.Error())
	}

	log.Info(ctx, map[string]interface{}{
		"spaceResourceID": resource.ID,
	}, "Space resource created successfully")
	return resource, nil
}

// LoadBySpace loads space resource by space ID
func (r *GormResourceRepository) LoadBySpace(ctx context.Context, spaceID *uuid.UUID) (*Resource, error) {
	res := Resource{}
	tx := r.db.Where("space_resources.space_id=?", *spaceID).First(&res)
	if tx.RecordNotFound() {
		log.Error(ctx, map[string]interface{}{
			"spaceID": spaceID.String(),
		}, "Could not find space resource by space ID")
		return nil, errors.NewNotFoundError("space resource", spaceID.String())
	}
	if tx.Error != nil {
		return nil, errors.NewInternalError(tx.Error.Error())
	}
	return &res, nil
}
