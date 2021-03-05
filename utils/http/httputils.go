package httputils

import (
	"path"
	"strconv"

	commonutils "github.com/alessiosavi/StreamingServer/utils/common"

	fileutils "github.com/alessiosavi/GoGPUtils/files"

	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

func ListAndServerGZIP(host string, _port int, gzipHandler fasthttp.RequestHandler) {
	port := strconv.Itoa(_port)
	log.Infof("ListAndServerGZIP | Trying estabilishing connection @[http://%s:%s]", host, port)
	err := fasthttp.ListenAndServe(host+":"+port, gzipHandler) // Try to start the server with input "host:port" received in input
	if err != nil {                                            // No luck, connection not succesfully. Probably port used ...
		log.Warn("ListAndServerGZIP | Port [", port, "] seems used :/")
		for i := 0; i < 10; i++ {
			port := strconv.Itoa(commonutils.Random(8081, 8090)) // Generate a new port to use
			log.Info("ListAndServerGZIP | Round ", strconv.Itoa(i), "] No luck! Connecting to anotother random port [@", port, "] ...")
			err := fasthttp.ListenAndServe(host+":"+port, gzipHandler) // Trying with the random port generate few step above
			if err == nil {                                            // Connection estabileshed! Not reached
				log.Infof("ListAndServerGZIP | Connection estabilished @[http://%s:%s]", host, port)
				break
			}
		}
	}
}

func ListAndServerSSL(host, _path, pub, priv string, _port int, gzipHandler fasthttp.RequestHandler) {
	pub = path.Join(_path, pub)
	priv = path.Join(_path, priv)
	if fileutils.FileExists(pub) && fileutils.FileExists(priv) {
		port := strconv.Itoa(_port)
		log.Infof("ListAndServerSSL | Trying estabilishing connection @[https://%s:%s]", host, port)
		err := fasthttp.ListenAndServeTLS(host+":"+port, pub, priv, gzipHandler) // Try to start the server with input "host:port" received in input
		if err != nil {                                                          // No luck, connection not succesfully. Probably port used ...
			log.Warn("ListAndServerSSL | Port [", port, "] seems used :/")
			for i := 0; i < 10; i++ {
				port := strconv.Itoa(commonutils.Random(8081, 8090)) // Generate a new port to use
				log.Info("ListAndServerSSL | Round ", i, "] No luck! Connecting to anotother random port [@"+port+"] ...")
				err := fasthttp.ListenAndServeTLS(host+":"+port, pub, priv, gzipHandler) // Trying with the random port generate few step above
				if err == nil {                                                          // Connection estabileshed! Not reached
					log.Infof("ListAndServerSSL | Connection estabilished @[https://%s:%s]", host, port)
					break
				}
			}
		}
	}
	log.Error("ListAndServerSSL | Unable to find certificates: pub[" + pub + "] | priv[" + priv + "]")
}

// Enhance the security with additional sec header
func SecureRequest(ctx *fasthttp.RequestCtx, ssl bool) {
	ctx.Response.Header.Set("Feature-Policy", "geolocation 'none'; microphone 'none'; camera 'self'")
	ctx.Response.Header.Set("Referrer-Policy", "no-referrer")
	ctx.Response.Header.Set("x-frame-options", "SAMEORIGIN")
	ctx.Response.Header.Set("X-Content-Type-Options", "nosniff")
	ctx.Response.Header.Set("X-Permitted-Cross-Domain-Policies", "none")
	ctx.Response.Header.Set("X-XSS-Protection", "1; mode=block")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	if ssl {
		ctx.Response.Header.Set("Content-Security-Policy", "upgrade-insecure-requests")
		ctx.Response.Header.Set("Strict-Transport-Security", "max-age=60; includeSubDomains; preload")
		ctx.Response.Header.Set("expect-ct", "max-age=60, enforce")
	}
}
