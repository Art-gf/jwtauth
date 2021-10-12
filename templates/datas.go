package templates

type User struct {
	Login       string `bson:"login,omitempty"`
	Guid        string `bson:"guid,omitempty"`
	UserHash    string `bson:"userhash,omitempty"`
	RefreshHash string `bson:"refhash,omitempty"`
}
