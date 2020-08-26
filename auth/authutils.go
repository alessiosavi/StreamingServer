package authutils

import (
	"bytes"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"

	basiccrypt "github.com/alessiosavi/StreamingServer/crypt"

	basicredis "github.com/alessiosavi/StreamingServer/database/redis"
	"github.com/alessiosavi/StreamingServer/datastructures"

	stringutils "github.com/alessiosavi/GoGPUtils/string"
	"github.com/go-redis/redis"
	"github.com/valyala/fasthttp"

	log "github.com/sirupsen/logrus"
)

// ====== HTTP CORE METHODS ======

// LoginUserHTTPCore is delegated to manage the "core process" of authentication. It use the username in input for retrieve the customer
// data from MongoDB. If the data is found, then the password in input will be compared with the one retrieved from the database
func LoginUserHTTPCore(username, password string, redisClient *redis.Client) error {
	var err error
	log.Debug("LoginUserHTTPCore | Verify if user [", username, "] is registered ...")
	log.Info("LoginUserHTTPCore | Getting value from DB ...")
	var User datastructures.User // Allocate a Person for store the DB result of next instruction
	if err = basicredis.GetValueFromDB(redisClient, username, &User); err == nil {
		log.Debug("LoginUserHTTPCore | Comparing password ...")
		if basiccrypt.VerifyPlainPasswords(password, User.Password, username+":"+password) { // Comparing password of the user from DB with the one in input
			log.Warn("LoginUserHTTPCore | Client credential authorizated !!! | User: ", User)
			return nil
		}
		log.Error("LoginUserHTTPCore | Passwords does not match!!")
		return errors.New("INVALID_PASSWORD")
	}
	log.Error("LoginUserHTTPCore | User is not registered [", username, "] | Error: ", err)
	return errors.New("USER [" + username + "] IS NOT REGISTERED!")
}

// RegisterUserHTTPCore is delegated to register the credential of the user into the Redis database.
// It estabilish the connection to MongoDB with a specialized function, then it create an user with the input data.
// After that, it ask to a delegated function to insert the data into Redis.
func RegisterUserHTTPCore(username, password string, redisClient *redis.Client) error {
	//	User := datastructures.User{Username: username, Password: basiccrypt.Encrypt([]byte(password), username+":"+password)} // Create the user
	log.Debug("RegisterUserHTTPCore | Registering [", username, ":", password, "]")
	if redisClient == nil {
		log.Error("RegisterUserHTTPCore | Impossible to connect to DB | ", redisClient)
		return errors.New("DB_UNAVAIBLE")
	}
	log.Debug("RegisterUserHTTPCore | Verifying if connection is available ...")
	if err := redisClient.Ping().Err(); err != nil {
		log.Error("RegisterUserHTTPCore | Redis ping: ", err)
		return err
	}
	log.Debug("RegisterUserHTTPCore | Connection enstabilished! Inserting data ...")
	// Store the password encrypting with the 'username:password' as key :/
	// TODO: Increase security
	var User datastructures.User
	if err := basicredis.GetValueFromDB(redisClient, username, &User); err == redis.Nil {
		log.Debug("RegisterUserHTTPCore | User [", username, "] does not exists, inserting into DB")
		User := datastructures.User{Username: username, Password: basiccrypt.Encrypt([]byte(password), username+":"+password)} // Create the user
		return basicredis.InsertValueIntoDB(redisClient, User.Username, User)
	}
	return errors.New("ALREADY_EXIST")

}

// VerifyCookieFromRedisHTTPCore is delegated to verify if the cookie of the customer is present on the DB (aka is logged).
// This method have only to verify if the token provided by the customer that use the API is present on RedisDB.
// In first instance it try to validate the input data. Then will continue connecting to Redis in order to retrieve the token of
// the customer. If the token is found, the customer is authorized to continue.
func VerifyCookieFromRedisHTTPCore(user, token string, redisClient *redis.Client) error {
	var err error
	log.Debug("VerifyCookieFromRedisHTTPCore | START | User: ", user, " | Token: ", token)
	if ValidateUsername(user) { // Verify that the credentials respect the rules
		if ValidateToken(token) { // Verify that the token respect the rules
			log.Debug("VerifyCookieFromRedisHTTPCore | Credential validated, retrieving token value from Redis ...")
			if dbToken, err := basicredis.GetTokenFromDB(redisClient, user); err == nil {
				log.Trace("VerifyCookieFromRedisHTTPCore | Data retrieved!")
				if strings.Compare(dbToken, token) == 0 {
					log.Info("VerifyCookieFromRedisHTTPCore | Token MATCH!! User is logged! | ", user, " | ", token)
					return nil
				}
				log.Error("VerifyCookieFromRedisHTTPCore | Token MISMATCH!! User is NOT logged! | ", user, " | TK: ", token, " | DB: ", dbToken)
				return errors.New("NOT_AUTHORIZED")
			}
			log.Error("VerifyCookieFromRedisHTTPCore | Token not present in DB: ", err)
			return errors.New("USER_NOT_LOGGED")
		}
		log.Error("VerifyCookieFromRedisHTTPCore | Token not valid :/ | Token: ", token)
		return errors.New("COOKIE_NOT_VALID")
	}
	log.Error("VerifyCookieFromRedisHTTPCore | Username is not valid!")
	return errors.New("USERNAME_NOT_VALID")
}

// DeleteUserHTTPCore is delegated to remove the given username from the DB
func DeleteUserHTTPCore(user, password, token string, redisClient *redis.Client) error {
	log.Info("DeleteCustomerHTTPCore | Removing -> User: ", user, " | Psw: ", password, " | Token: ", token)
	log.Debug("DeleteCustomerHTTPCore | Validating username and password ...")
	if ValidateCredentials(user, password) {
		log.Debug("DeleteCustomerHTTPCore | Validating token ...")
		if ValidateToken(token) {
			log.Debug("DeleteCustomerHTTPCore | Input validated! | Retrieving data from DB ...")
			var User datastructures.User                                                // Allocate a Person for store the DB result of next instruction
			if err := basicredis.GetValueFromDB(redisClient, user, &User); err == nil { // User found... Let's now compare the password ..
				log.Debug("DeleteCustomerHTTPCore | Comparing password ...")
				if strings.Compare(User.Password, password) == 0 { // Comparing password of the user from DB with the one in input
					log.Warn("DeleteCustomerHTTPCore | Password match !! | Retrieving token from Redis ...")
					var dbToken string
					if err := basicredis.GetValueFromDB(redisClient, user, &dbToken); err == nil {
						log.Debug("DeleteCustomerHTTPCore | Data retrieved [", dbToken, "]! | Comparing token ...")
						if strings.Compare(token, dbToken) == 0 {
							log.Info("DeleteCustomerHTTPCore | Token match!! | Deleting customer [", user, "] from MongoDB ..")
							if err = basicredis.RemoveValueFromDB(redisClient, user); err != nil {
								log.Error("DeleteCustomerHTTPCore | Error during delete of user :( | User: ", user, " | Session: ", redisClient, " | Error: ", err)
								return errors.New("KO_DELETE_REDIS")
							}
							log.Info("DeleteCustomerHTTPCore | Customer [", user, "] deleted!! | Removing token")
							if err = basicredis.RemoveValueFromDB(redisClient, user); err == nil {
								log.Info("DeleteCustomerHTTPCore | Token removed from Redis | Bye bye [", User, "]")
								return nil
							}
						}
						log.Error("DeleteCustomerHTTPCore | User [", user, "] have tried to delete the account with a valid password but with an invalid token!! | ERR: ", err)
						log.Error("DeleteCustomerHTTPCore | TokenDB: ", token, " | Customer: ", User)
						return errors.New("TOKEN_MANIPULATED")
					}
					log.Error("DeleteCustomerHTTPCore | User [", user, "] not logged in!! ERR: ", err)
					return errors.New("NOT_LOGGED")
				}
				log.Error("DeleteCustomerHTTPCore | Passwords does not match!!")
				return errors.New("PSW")
			}
			log.Error("DeleteCustomerHTTPCore | User [", user, "] is not registered yet!!")
			return errors.New("NOT_REGISTER")
		}
		log.Error("DeleteCustomerHTTPCore | Token [", token, "] is not valid!")
		return errors.New("TOKEN")
	}
	log.Error("DeleteCustomerHTTPCore | Credentials [Usr: ", user, " | Psw: ", password, "] not valid!!")
	return errors.New("NOT_REGISTER")
}

// ====== HTTP UTILS METHODS ======

// ParseAuthCredentialFromHeaders is delegated to extract the username and the password from the BasicAuth header provided by the request
// In case of error will return two emtpy string; in case of success will return (username,password)
func ParseAuthCredentialFromHeaders(auth []byte) (string, string) {
	basicAuthPrefix := []byte("Basic ")
	if len(auth) <= len(basicAuthPrefix) {
		log.Debug("parseAuthCredentialFromHeaders | Headers does not contains no auth encoded")
		return "", ""
	}
	payload, err := base64.StdEncoding.DecodeString(string(auth[len(basicAuthPrefix):])) // Extract only the string after the "Basic "
	log.Info("parseAuthCredentialFromHeaders | Payload extracted: ", string(payload))
	if err != nil {
		log.Error("parseAuthCredentialFromHeaders | STOP | KO | ", err)
		return "", "" // error cause
	}
	pair := bytes.SplitN(payload, []byte(":"), 2) // Extract the username [0] and password [1] separated by the ':'
	if len(pair) == 2 {                           // Only "username:password" admitted!
		log.Info("parseAuthCredentialFromHeaders | Payload splitted: ", string(pair[0]), " | ", string(pair[1]))
		return string(pair[0]), string(pair[1])
	}
	log.Error("parseAuthCredentialFromHeaders | Impossible to split the payload :/ | Payload: ", payload, " | Basic: ", string(auth))
	return "", "" // error cause
}

// ValidateCredentials is wrapper for the multiple method for validate the input parameters
func ValidateCredentials(user string, pass string) bool {
	if ValidateUsername(user) && PasswordValidation(pass) {
		return true
	}
	return false
}

// PasswordValidation execute few check on the password in input
func PasswordValidation(password string) bool {
	if stringutils.IsBlank(password) {
		log.Warn("PasswordValidation | Password is empty :/")
		return false
	}
	if len(password) < 4 || len(password) > 32 {
		log.Warn("PasswordValidation | Password len not valid")
		return false
	}
	myReg := regexp.MustCompile("^[a-zA-Z0-9'\"+-.><=,;{}!@#$%^&_*()]{4,32}$") // Only letter + number
	if !myReg.MatchString(password) {                                          // If the input don't match the regexp
		log.Warn("PasswordValidation | Password have strange character :/ [", password, "]")
		return false
	}
	log.Info("PasswordValidation | Password [", password, "] VALIDATED!")
	return true
}

// ValidateUsername execute few check on the username in input
func ValidateUsername(username string) bool {
	if stringutils.IsBlank(username) {
		log.Warn("ValidateUsername | Username is empty :/")
		return false
	}
	if len(username) < 4 || len(username) > 32 {
		log.Warn("ValidateUsername | Username len not valid")
		return false
	}
	myReg := regexp.MustCompile("^[a-zA-Z0-9-_@]{4,32}$") // The string have to contains ONLY (letter OR number)
	if !myReg.MatchString(username) {                     // the input doesn't match the regexp
		log.Warn("ValidateUsername | Username have strange character :/ [", username, "]")
		return false
	}
	log.Debug("ValidateUsername | Username [", username, "] VALIDATED!")
	return true
}

// ValidateToken execute few check on the token in input
func ValidateToken(token string) bool {
	log.Debug("ValidateToken | Validating [", token, "] ...")
	if stringutils.IsBlank(token) {
		log.Warn("ValidateToken | Token is empty :/")
		return false
	}
	if !(len(token) > 0 && len(token) < 100) {
		log.Warn("ValidateToken | Token len not in 0<token<100 :/ [found ", len(token), "]")
		return false
	}
	log.Debug("ValidateToken | Token [", token, "] VALIDATED!")
	return true
}

// RedirectCookie return the cookie by the parameter in input and reassing to the response
func RedirectCookie(ctx *fasthttp.RequestCtx, expire int) string {
	var cookie string
	cookie = string(ctx.Request.Header.Cookie("GoLog-Token"))
	if stringutils.IsBlank(cookie) {
		cookie = "USER_NOT_LOGGED_IN"
	}
	ctx.Response.Header.SetCookie(CreateCookie("GoLog-Token", cookie, expire))
	return cookie
}

// ParseAuthCredentialsFromRequestBody is delegated to extract the username and the password from the request body
func ParseAuthCredentialsFromRequestBody(ctx *fasthttp.RequestCtx) (string, string) {
	// Extracting data from request
	user := string(ctx.FormValue("user"))
	pass := string(ctx.FormValue("pass"))
	return user, pass
}

//CreateCookie Method that return a cookie valorized as input (GoLog-Token as key)
func CreateCookie(key string, value string, expire int) *fasthttp.Cookie {
	if strings.Compare(key, "") == 0 {
		key = "GoLog-Token"
	}
	log.Debug("CreateCookie | Creating Cookie | Key: ", key, " | Val: ", value)
	authCookie := fasthttp.Cookie{}
	authCookie.SetKey(key)
	authCookie.SetValue(value)
	authCookie.SetMaxAge(expire)
	authCookie.SetHTTPOnly(true)
	authCookie.SetPath("/")
	return &authCookie
}
