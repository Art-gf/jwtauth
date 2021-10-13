package service

// JSON templates

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

type LoginResponse struct {
	Guid string `json:"guid"`
}

type AuthorizeRequest struct {
	Guid string `json:"guid"`
}

type AuthorizeResponse struct {
	AccessToken  string `json:"access"`
	RefreshToken string `json:"refresh"`
}

type RefreshRequest struct {
	AccessToken  string `json:"access"`
	RefreshToken string `json:"refresh"`
}

type RefreshResponse struct {
	Message      string `json:"message"`
	AccessToken  string `json:"access"`
	RefreshToken string `json:"refresh"`
}
