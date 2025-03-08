package domain

import "time"

type Role int32

const (
	USER     Role = 0
	EMPLOYEE Role = 1
	ADMIN    Role = 2
)

type User struct {
	ID        string `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	Email     string `gorm:"unique"`
	Password  string
	Role      Role
	CreatedAt time.Time
	UpdatedAt time.Time
}
