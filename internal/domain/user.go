package domain

import "time"

type User struct {
	ID        string `gorm:"primaryKey;type:uuid;default:uuid_generate_v4()"`
	Email     string `gorm:"unique"`
	Password  string
	Role      string
	CreatedAt time.Time
	UpdatedAt time.Time
}
