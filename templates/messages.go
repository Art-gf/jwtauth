package templates

type ErrorMessage struct {
	Message string `json:"Message"`
}

type RegisterRequest struct {
	Login string `json:"name"`
	Pass  string `json:"password"`
}

type LoginRequest struct {
	Login string `json:"name"`
	Pass  string `json:"password"`
}

type AuthorizeRequest struct {
	Guid uint64 `json:"guid"`
}
type AuthorizeResponse struct {
	AccessToken  string `json:"access"`
	RefreshToken string `json:"refresh"`
}

type SecuredRequest struct {
	AccessToken string `json:"access"`
}
type SecureResponse struct {
	ExpTime string `json:"tokenLeftTime"`
}

type RefreshRequest struct {
	AccessToken  string `json:"access"`
	RefreshToken string `json:"refresh"`
}
type RefreshResponse struct {
	AccessToken  string `json:"access"`
	RefreshToken string `json:"refresh"`
	Message      string
}
