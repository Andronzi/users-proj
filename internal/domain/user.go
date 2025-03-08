package domain

import "time"

type Role string

const (
	USER     Role = "USER"
	EMPLOYEE Role = "EMPLOYEE"
	ADMIN    Role = "ADMIN"
)

type User struct {
	ID        string `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	Email     string `gorm:"unique"`
	Password  string
	Role      Role
	CreatedAt time.Time
	UpdatedAt time.Time
}
