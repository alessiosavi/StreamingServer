package datastructures

// User struct is delegated to save the information related to the user
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// Response structure used for populate the json response for the RESTfull HTTP API
type Response struct {
	Status      bool        `json:"Status"`      // Status of response [true,false] OK, KO
	ErrorCode   string      `json:"ErrorCode"`   // Code linked to the error (KO)
	Description string      `json:"Description"` // Description linked to the error (KO)
	Data        interface{} `json:"Data"`        // Generic data to return in the response
}

// Configuration is the structure for handle the configuration data
type Configuration struct {
	Host    string // Hostname to bind the service
	Port    int    // Port to bind the service
	Version string
	SSL     struct {
		Path    string
		Cert    string
		Key     string
		Enabled bool
	}
	Redis struct {
		Host  string
		Port  string
		Token struct {
			Expire int
			DB     int
		}
	}
	Log struct {
		Level string
		Path  string
		Name  string
	}
	Video struct {
		Path string
	}
}
