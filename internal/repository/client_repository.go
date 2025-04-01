package repository

import (
	"context"
	"user_project/internal/domain"

	"gorm.io/gorm"
)

type ClientRepository struct {
	db *gorm.DB
}

func NewClientRepository(db *gorm.DB) *ClientRepository {
	return &ClientRepository{db: db}
}

func (r *ClientRepository) CreateClient(ctx context.Context, client *domain.Client) error {
	return r.db.WithContext(ctx).Create(client).Error
}

func (r *ClientRepository) GetClientByID(ctx context.Context, id string) (*domain.Client, error) {
	var client domain.Client
	if err := r.db.WithContext(ctx).Where("id = ?", id).First(&client).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

func (r *ClientRepository) SaveAuthorizationCode(ctx context.Context, code *domain.AuthorizationCode) error {
	return r.db.WithContext(ctx).Create(code).Error
}

func (r *ClientRepository) GetAuthorizationCode(ctx context.Context, code string) (*domain.AuthorizationCode, error) {
	var authCode domain.AuthorizationCode
	if err := r.db.WithContext(ctx).Where("code = ?", code).First(&authCode).Error; err != nil {
		return nil, err
	}
	return &authCode, nil
}

func (r *ClientRepository) CreateSession(ctx context.Context, session *domain.Session) error {
	return r.db.WithContext(ctx).Create(session).Error
}

func (r *ClientRepository) GetSession(ctx context.Context, id string) (*domain.Session, error) {
	var session domain.Session
	if err := r.db.WithContext(ctx).First(&session, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &session, nil
}
