package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	stringutils "github.com/alessiosavi/GoGPUtils/string"
	"path"
	"strings"
	"time"

	authutils "github.com/alessiosavi/StreamingServer/auth"
	basiccrypt "github.com/alessiosavi/StreamingServer/crypt"

	commonutils "github.com/alessiosavi/StreamingServer/utils/common"
	httputils "github.com/alessiosavi/StreamingServer/utils/http"

	fileutils "github.com/alessiosavi/GoGPUtils/files"

	basicredis "github.com/alessiosavi/StreamingServer/database/redis"
	"github.com/alessiosavi/StreamingServer/datastructures"
	"github.com/go-redis/redis"
	"github.com/onrik/logrus/filename"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/expvarhandler"

	// Very nice log library
	log "github.com/sirupsen/logrus"
)

func main() {
	// ==== SET LOGGING
	Formatter := new(log.TextFormatter)
	Formatter.TimestampFormat = "Jan _2 15:04:05.000000000"
	Formatter.FullTimestamp = true
	Formatter.ForceColors = true
	log.AddHook(filename.NewHook()) // Print filename + line at every log
	log.SetFormatter(Formatter)

	log.Debugln("Test")
	cfg := commonutils.VerifyCommandLineInput()
	log.SetLevel(commonutils.SetDebugLevel(cfg.Log.Level))

	// ==== CONNECT TO REDIS ====
	redisClient, err := basicredis.ConnectToDb(cfg.Redis.Host, cfg.Redis.Port, cfg.Redis.Token.DB)
	if err != nil {
		log.Fatal("Unable to connect to redis! | Err: " + err.Error())
		return
	}
	defer redisClient.Close()
	handleRequests(cfg, redisClient)
}

// handleRequests Is delegated to map (BIND) the API methods to the HTTP URL
// It uses a gzip handler that is usefully for reduce bandwidth usage while interacting with the middleware function
func handleRequests(cfg datastructures.Configuration, redisClient *redis.Client) {
	m := func(ctx *fasthttp.RequestCtx) {
		if cfg.SSL.Enabled {
			log.Debug("handleRequests | SSL is enabled!")
		}
		httputils.SecureRequest(ctx, cfg.SSL.Enabled)
		ctx.Response.Header.Set("StreamingServer", "$v0.0.3")

		// Avoid to print stats for the expvar handler
		if strings.Compare(string(ctx.Path()), "/stats") != 0 {
			log.Info("\n|REQUEST --> ", ctx, " \n|Headers: ", ctx.Request.Header.String(), "| Body: ", string(ctx.PostBody()))
		}
		var err error
		switch string(ctx.Path()) {
		case "/auth/login":
			err = authLoginWrapper(ctx, redisClient, cfg) // Login functionality [Test purpose]
		case "/auth/register":
			err = authRegisterWrapper(ctx, redisClient) // Register user into the DB [Test purpose]
		case "/auth/delete":
			err = deleteCustomerHTTP(ctx, redisClient)
		case "/auth/verify":
			err = verifyCookieFromRedisHTTP(ctx, redisClient) // Verify if user is authorized to use the service
		case "/stream":
			streamVideos(ctx, cfg)
		case "/stats":
			expvarhandler.ExpvarHandler(ctx)
		case "/play":
			err = playVideo(ctx, cfg, redisClient)
		case "/activate":
			err = activateUser(ctx, cfg, redisClient)
		default:
			ctx.WriteString("The url " + string(ctx.URI().RequestURI()) + string(ctx.QueryArgs().QueryString()) + " does not exist :(\n")
			ctx.Response.SetStatusCode(404)
		}
		log.Println(err)
		ctx.WriteString(err.Error())
	}
	// ==== GZIP HANDLER ====
	// The gzipHandler will serve a compress request only if the client request it with headers (Content-Type: gzip, deflate)
	gzipHandler := fasthttp.CompressHandlerLevel(m, fasthttp.CompressBestCompression) // Compress data before sending (if requested by the client)
	ssl := ""
	if cfg.SSL.Enabled {
		ssl = "s"
	}
	log.Infof("HandleRequests | Binding services to @[http%s://"+cfg.Host+":%d]", ssl, cfg.Port)

	// ==== SSL HANDLER + GZIP if requested ====
	if cfg.SSL.Enabled {
		httputils.ListAndServerSSL(cfg.Host, cfg.SSL.Path, cfg.SSL.Cert, cfg.SSL.Key, cfg.Port, gzipHandler)
	}
	// ==== Simple GZIP HANDLER ====
	httputils.ListAndServerGZIP(cfg.Host, cfg.Port, gzipHandler)
	log.Trace("HandleRequests | STOP")
}

func activateUser(ctx *fasthttp.RequestCtx, cfg datastructures.Configuration, redisClient *redis.Client) error {
	var err error
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	if !cfg.Video.ActivateSecret {
		err = errors.New("ACTIVATE_DISABLED")
		json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Activation functionality is disabled", ErrorCode: err.Error(), Data: nil})
		return err
	}

	user, pass := authutils.ParseAuthCredentialsFromRequestBody(ctx)
	if stringutils.IsBlank(user) {
		log.Warning("ActivateUser | User parameter is empty!")
		err = errors.New("USER_PARM_NOT_PROVIDED")
		json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "User parameter not provided", ErrorCode: err.Error(), Data: nil})
		return err
	}
	if stringutils.IsBlank(pass) {
		log.Warning("ActivateUser | Pass parameter is empty!")
		err = errors.New("PASS_PARM_NOT_PROVIDED")
		json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Pass parameter not provided", ErrorCode: err.Error(), Data: nil})
		return err
	}

	if strings.Compare(cfg.Video.Secret, stringutils.Trim(pass)) != 0 {
		log.Warningf("ActivateUser | Password provided [%s] does not match the secret [%s]", pass, cfg.Video.Secret)
		err = errors.New("PASS_NOT_MATCH_SECRET")
		json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Password does not match the secret token in configuration", ErrorCode: err.Error(), Data: nil})
		return err
	}

	var User datastructures.User // Allocate a Person for store the DB result of next instruction
	if err = basicredis.GetValueFromDB(redisClient, user, &User); err == nil {
		if User.Active {
			log.Warningf("ActivateUser | User [%s] is already activated...", user)
			err = errors.New("USER_ALREADY_ACTIVE")
			json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "User [" + user + "] is already activated", ErrorCode: err.Error(), Data: nil})
			return err
		}
		User.Active = true
		if err = basicredis.InsertValueIntoDB(redisClient, user, User); err == nil {
			log.Infof("ActivateUser | User [%s] was activated correctly!", user)
			json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "User [" + user + "] is activated", ErrorCode: "nil", Data: nil})
			return nil
		}
	}
	return err
}

// playVideo is delegated to play the videos in input
func playVideo(ctx *fasthttp.RequestCtx, cfg datastructures.Configuration, redisClient *redis.Client) error {
	if err := verifyCookieFromRedisHTTP(ctx, redisClient); err == nil {
		video := string(ctx.FormValue("video"))
		if stringutils.IsBlank(video) {
			ctx.Response.Header.SetContentType("application/json; charset=utf-8")
			return json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "video parameter is empty", ErrorCode: "EMPTY_VIDEO_PARM", Data: nil})

		}
		f := path.Join(cfg.Video.Path, video)
		if !fileutils.FileExists(f) {
			ctx.Response.Header.SetContentType("application/json; charset=utf-8")
			return json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "video " + video + " does not exists", ErrorCode: "VIDEO_NOT_FOUND", Data: nil})

		}
		ctx.SendFile(f)
	} else {
		ctx.Response.Header.SetContentType("application/json; charset=utf-8")
		return json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: err.Error(), ErrorCode: "NOT_LOGGED", Data: nil})
	}
	return nil
}

// streamVideos is delegated to verify if the user is logged in and expose the video to stream
func streamVideos(ctx *fasthttp.RequestCtx, cfg datastructures.Configuration) {
	ctx.Response.Header.SetContentType("text/html; charset=utf-8")
	files, err := fileutils.ListFiles(cfg.Video.Path)
	if err != nil {
		panic(err)
	}
	var s strings.Builder
	var ssl string
	if cfg.SSL.Enabled {
		ssl = "s"
	}
	s.WriteString("<ol>\n")
	for _, f := range files {
		f = strings.Replace(f, cfg.Video.Path, "", 1)
		url := fmt.Sprintf(`<li><a href="http%s://%s/play?video=%s">%s</a></li>`, ssl, string(ctx.Request.Host()), f, f)
		//s.WriteString(`<li><a href="http://` + string(ctx.Request.Host()) + `/play?video=` + f + `">` + f + "</a></li>" + "\n")
		s.WriteString(url)
	}
	s.WriteString("</ol>")
	ctx.WriteString(s.String() + "\n")
}

// authRegisterWrapper is the authentication wrapper for register the client into the service.
// It has to parse the credentials of the customers and register the username and the password into the DB.
func authRegisterWrapper(ctx *fasthttp.RequestCtx, redisClient *redis.Client) error {
	log.Debug("AuthRegisterWrapper | Starting register functionalities! | Parsing username and password ...")
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	ctx.Request.Header.Set("WWW-Authenticate", `Basic realm="Restricted"`)
	username, password := parseAuthenticationCoreHTTP(ctx) // Retrieve the username and password encoded in the request
	if authutils.ValidateCredentials(username, password) {
		log.Debug("AuthRegisterWrapper | Input validated | User: ", username, " | Pass: ", password, " | Calling core functionalities ...")
		if err := authutils.RegisterUserHTTPCore(username, password, redisClient); err == nil {
			log.Warn("AuthRegisterWrapper | Customer insert with success! | ", username, ":", password)
			return json.NewEncoder(ctx).Encode(datastructures.Response{Status: true, Description: "User inserted!", ErrorCode: username + ":" + password, Data: nil})
		} else {
			return commonutils.AuthRegisterErrorHelper(ctx, err.Error(), username, password)
		}
	}
	log.Info("AuthRegisterWrapper | Error parsing credential!! | ", username, ":", password)
	return json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Error parsing credential", ErrorCode: "Wrong input or fatal error", Data: nil})

}

// deleteCustomerHTTP wrapper for verify if the user is logged
func deleteCustomerHTTP(ctx *fasthttp.RequestCtx, redisClient *redis.Client) error {
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	log.Debug("DeleteCustomerHTTP | Retrieving username ...")
	user, psw := parseAuthenticationCoreHTTP(ctx)
	log.Debug("DeleteCustomerHTTP | Retrieving token ...")
	token := parseTokenFromRequest(ctx)
	log.Debug("DeleteCustomerHTTP | Retrieving cookie from redis ...")
	if err := authutils.DeleteUserHTTPCore(user, psw, token, redisClient); err == nil {
		return json.NewEncoder(ctx).Encode(datastructures.Response{Status: true, Description: "User " + user + " removed!", ErrorCode: "", Data: nil})
	} else {
		return json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "User " + user + " NOT removed!", ErrorCode: err.Error(), Data: nil})
	}
}

// authLoginWrapper is the authentication wrapper for login functionality. It allows the customers that have completed the registration phase to log in and receive the mandatory
// token for interact with the services
// In order to be compliant with as many protocol as possible, the method try to find the two parameter needed (user,pass) sequentially from:
// BasicAuth headers; query args; GET args; POST args. It manages few error cause just for debug purpose
// The login functionality can be accomplished using different methods:
// BasicAuth headers: example ->from browser username:password@$URL/auth/login| curl -vL --user "username:password $URL/auth/login"
// GET Request: example -> from browser $URL/auth/login?user=username&pass=password | curl -vL $URL/auth/login?user=username&pass=password
// POST Request: example -> curl -vL $URL/auth/login -d 'user=username&pass=password'
func authLoginWrapper(ctx *fasthttp.RequestCtx, redisClient *redis.Client, cfg datastructures.Configuration) error {
	log.Info("AuthLoginWrapper | Starting authentication | Parsing authentication credentials")
	ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	username, password := parseAuthenticationCoreHTTP(ctx) // Retrieve the username and password encoded in the request from BasicAuth headers, GET & POST
	if authutils.ValidateCredentials(username, password) { // Verify if the input parameter respect the rules ...
		log.Debug("AuthLoginWrapper | Input validated | User: ", username, " | Pass: ", password, " | Calling core functionalities ...")
		if err := authutils.LoginUserHTTPCore(username, password, redisClient); err == nil { // Login phase
			log.Debug("AuthLoginWrapper | Login successfully! Generating token!")
			token := basiccrypt.GenerateToken(username, password) // Generate a simple md5 hashed token
			log.Info("AuthLoginWrapper | Inserting token into Redis ", token)
			if err = basicredis.InsertTokenIntoDB(redisClient, username, token, time.Second*time.Duration(cfg.Redis.Token.Expire)); err != nil {
				return err
			}
			// insert the token into the DB
			log.Info("AuthLoginWrapper | Token inserted! All operation finished correctly! | Setting token into response")
			authcookie := authutils.CreateCookie("GoLog-Token", token, cfg.Redis.Token.Expire)
			usernameCookie := authutils.CreateCookie("username", username, cfg.Redis.Token.Expire)
			if cfg.SSL.Enabled {
				authcookie.SetSecure(true)
				usernameCookie.SetSecure(true)
			}
			ctx.Response.Header.SetCookie(authcookie)     // Set the token into the cookie headers
			ctx.Response.Header.SetCookie(usernameCookie) // Set the token into the cookie headers
			ctx.Response.Header.Set("GoLog-Token", token) // Set the token into a custom headers for future security improvements
			log.Warn("AuthLoginWrapper | Client logged in successfully!! | ", username, ":", password, " | Token: ", token)
			return json.NewEncoder(ctx).Encode(datastructures.Response{Status: true, Description: "User logged in!", ErrorCode: username + ":" + password, Data: token})
		} else {
			return commonutils.AuthLoginWrapperErrorHelper(ctx, err.Error(), username, password)
		}
	} else { // error parsing credential
		log.Info("AuthLoginWrapper | Error parsing credential!! |", username+":"+password)
		ctx.Response.Header.DelCookie("GoLog-Token")
		ctx.Error(fasthttp.StatusMessage(fasthttp.StatusUnauthorized), fasthttp.StatusUnauthorized)
		ctx.Response.Header.Set("WWW-Authenticate", "Basic realm=Restricted")
		//err := json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Error parsing credential", ErrorCode: "Missing or manipulated input", Data: nil})
		//commonutils.Check(err, "AuthLoginWrapper")
	}
	return nil
}

// parseAuthenticationCoreHTTP The purpose of this method is to decode the username and the password encoded in the request.
// It has to recognize if the parameters are sent in the body of the request OR in the payload of the BasicAuth Header.
// In first instance he tries if the prefix of the BasicAuth is present in the headers. If found will delegate to extract the data to
// another function specialized to extract the data from the BasicAuth header.
// If the BasicAuth header is not provided, then the method will delegate the request to a function specialized for parse the data
// from the body of the request
func parseAuthenticationCoreHTTP(ctx *fasthttp.RequestCtx) (string, string) {
	basicAuthPrefix := []byte("Basic ")              // BasicAuth template prefix
	auth := ctx.Request.Header.Peek("Authorization") // Get the Basic Authentication credentials from headers
	log.Info("ParseAuthenticationHTTP | Auth Headers: [", string(auth), "]")
	if bytes.HasPrefix(auth, basicAuthPrefix) { // Check if the login is executed using the BasicAuth headers
		log.Debug("ParseAuthenticationHTTP | Logging-in from BasicAuth headers ...")
		return authutils.ParseAuthCredentialFromHeaders(auth) // Call the delegated method for extract the credentials from the Header
	} // In other case call the delegated method for extract the credentials from the body of the Request
	log.Info("ParseAuthenticationCoreHTTP | Credentials not in Headers, retrieving from body ...")
	user, pass := authutils.ParseAuthCredentialsFromRequestBody(ctx) // Used for extract user and password from the request
	if stringutils.IsBlank(user) {
		log.Info("ParseAuthenticationCoreHTTP | Username not in body, retrieving from cookie ...")
		user = string(ctx.Request.Header.Cookie("username"))
	}
	return user, pass
}

// verifyCookieFromRedisHTTP wrapper for verify if the user is logged
func verifyCookieFromRedisHTTP(ctx *fasthttp.RequestCtx, redisClient *redis.Client) error {
	log.Debug("VerifyCookieFromRedisHTTP | Retrieving username ...")
	user, _ := parseAuthenticationCoreHTTP(ctx)
	log.Debug("VerifyCookieFromRedisHTTP | Retrieving token ...")
	token := parseTokenFromRequest(ctx)
	log.Debug("VerifyCookieFromRedisHTTP | Retrieving cookie from redis ...")
	//if err = authutils.VerifyCookieFromRedisHTTPCore(user, token, redisClient); err != nil { // Verify if a user is authorized to use the service
	//ctx.Response.Header.SetContentType("application/json; charset=utf-8")
	//json.NewEncoder(ctx).Encode(datastructures.Response{Status: false, Description: "Not logged in!", ErrorCode: err.Error(), Data: nil})
	//}
	//return err
	return authutils.VerifyCookieFromRedisHTTPCore(user, token, redisClient)
}

// parseTokenFromRequest is delegated to retrieve the token encoded in the request. The token can be sent in two different way.
// In first instance the method will try to find the token in the cookie. If the cookie is not provided in the cookie,
// then the research will continue analyzing the body of the request (URL ARGS,GET,POST).
// In case of token not found, an empty string will be returned
func parseTokenFromRequest(ctx *fasthttp.RequestCtx) string {
	token := string(ctx.Request.Header.Cookie("GoLog-Token")) // GoLog-Token is the hardcoded name of the cookie
	log.Info("ParseTokenFromRequest | Checking if token is in the cookie ...")
	if strings.Compare(token, "") == 0 { // No cookie provided :/ Checking in the request
		log.Warn("ParseTokenFromRequest | Token is not in the cookie, retrieving from the request ...")
		token = string(ctx.FormValue("token")) // Extracting the token from the request (ARGS,GET,POST)
		if strings.Compare(token, "") == 0 {   // No token provided in the request
			log.Warn("ParseTokenFromRequest | Can not find the token! ...")
			return "" // "COOKIE_NOT_PRESENT"
		}
	}
	log.Info("ParseTokenFromRequest | Token found:", token)
	return token
}
