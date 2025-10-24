package user

import "boge.dev/golang-api/base"

type UpdateUser struct {
	Firstname *string `json:"first_name,omitempty"`
	Lastname  *string `json:"last_name,omitempty"`
	Email     *string `json:"email,omitempty"`
	base.BaseModel
}
