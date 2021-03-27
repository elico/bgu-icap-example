/*
An example of how to use go-icap.

Run this program and Squid on the same machine.
Put the following lines in squid.conf:

acl GET method GET

icap_enable on
icap_service service_req reqmod_precache icap://127.0.0.1:1344/injectjs/
adaptation_access service_req allow GET
adaptation_access service_req deny all

(The ICAP server needs to be started before Squid is.)

Set your browser to use the Squid proxy.

 Some Refrences:
 - https://groups.google.com/forum/#!topic/golang-nuts/J-Y4LtdGNSw
*/
package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"

	"github.com/elico/icap"
	"github.com/patrickmn/go-cache"
	"gopkg.in/redis.v3"
)

var (
	isTag          = "HTML-JS-Injector"
	debug          *bool
	address        *string
	maxConnections *string
	redisAddress   *string
	fullOverride   = false
	upnkeyTimeout  *int
	useGoCache     *bool
	err            error
	letters        = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
)

var goCacheLocal *cache.Cache
var redisDB redis.Client

// GlobalHTTPClient --
var GlobalHTTPClient *http.Client

func overrideExists(req *icap.Request) bool {
	if *debug {
		fmt.Println("Checking Override")
	}
	if fullOverride {
		if *debug {
			fmt.Println("Full Override active")
		}
		return true
	}
	if _, acceptExists := req.Request.Header["Accept"]; acceptExists {
		if *debug {
			fmt.Println(req.Request.Header["Accept"][0])
		}
		if strings.Contains(req.Request.Header["Accept"][0], "MoreCache/Override") {
			if *debug {
				fmt.Println("Override true")
			}
			return true
		}
	}
	if *debug {
		fmt.Println("Override false")
	}
	return false
}

func noCache(req *icap.Request) bool {
	if *debug {
		fmt.Println("Checking Request or response for \"no-cache\" => ")
	}

	if _, cacheControlExists := req.Request.Header["Cache-Control"]; cacheControlExists {
		if *debug {
			fmt.Println("Cache-Control Exists in the request: ")
			fmt.Println(req.Request.Header["Cache-Control"][0])
		}
		if strings.Contains(req.Request.Header["Cache-Control"][0], "no-cache") {
			if *debug {
				fmt.Println("\"no-cache\" Exists in the request!")
			}
			return true
		}
	}
	if _, cacheControlExists := req.Response.Header["Cache-Control"]; cacheControlExists {
		if *debug {
			fmt.Println("Cache-Control Exists in the response: ")
			fmt.Println("Cache-Control Header =>", reflect.TypeOf(req.Response.Header["Cache-Control"]))

			fmt.Println("Reflect tpyeof Cache-Control Header =>", reflect.TypeOf(req.Response.Header["Cache-Control"]))
			fmt.Println("len Cache-Control Header =>", len(req.Response.Header["Cache-Control"]))
			fmt.Println(req.Response.Header["Cache-Control"])
		}
		if len(req.Response.Header["Cache-Control"]) > 0 && strings.Contains(strings.Join(req.Response.Header["Cache-Control"], ", "), "no-cache") {
			fmt.Println("\"no-cache\" Exists in the response!")
			return true
		}
	}

	if *debug {
		fmt.Println("Cache-Control headers Doesn't Exists in this requset and response")
	}
	return false
}

func wrongMethod(req *icap.Request) bool {
	if *debug {
		fmt.Println("Checking Request method => ", req.Request.Method, req.Request.URL.String())
	}

	if req.Request.Method == "GET" {
		return false
	}
	return true

}

func htmlJSInject(w icap.ResponseWriter, req *icap.Request) {
	localDebug := false
	useTProxy := false
	if strings.Contains(req.URL.RawQuery, "debug=1") {
		localDebug = true
	}
	if strings.Contains(req.URL.RawQuery, "tproxy=1") {
		useTProxy = true
	}

	h := w.Header()
	h.Set("isTag", isTag)
	h.Set("Service", "HTML JS Injector ICAP serivce")

	if *debug {
		fmt.Fprintln(os.Stderr, "Printing the full ICAP request")
		fmt.Fprintln(os.Stderr, req)
		fmt.Fprintln(os.Stderr, req.Request)
		fmt.Fprintln(os.Stderr, req.Response)
	}
	switch req.Method {
	case "OPTIONS":
		h.Set("Methods", "REQMOD, RESPMOD")
		h.Set("Options-TTL", "1800")
		h.Set("Allow", "204, 206")
		h.Set("Preview", "0")
		h.Set("Transfer-Preview", "*")
		h.Set("Max-Connections", *maxConnections)
		h.Set("X-Include", "X-Client-IP, X-Authenticated-Groups, X-Authenticated-User, X-Subscriber-Id, X-Server-Ip, X-Store-Id")
		w.WriteHeader(200, nil, false)
	case "REQMOD":
		modified := false
		nullBody := false
		allow206 := false
		allow204 := false
		hasClientIPHeader := false

		if _, allow204Exists := req.Header["Allow"]; allow204Exists {
			if strings.Contains(req.Header["Allow"][0], "204") {
				allow204 = true
			}
		}

		if *debug || localDebug {
			for k, v := range req.Header {
				fmt.Fprintln(os.Stderr, "The ICAP headers:")
				fmt.Fprintln(os.Stderr, "key size:", len(req.Header[k]))
				fmt.Fprintln(os.Stderr, "key:", k, "value:", v)
			}
		}

		xClientIP := req.Header.Get("X-Client-IP")

		if govalidator.IsIP(xClientIP) {
			hasClientIPHeader = true
		}
		if hasClientIPHeader && (*debug || localDebug) {
			fmt.Fprintln(os.Stderr, "IP:", xClientIP, "Requested-URL:", req.Request.URL.String())
		}

		if _, encapsulationExists := req.Header["Encapsulated"]; encapsulationExists {
			if strings.Contains(req.Header["Encapsulated"][0], "null-body=") {
				nullBody = true
			}
		}

		if _, allow206Exists := req.Header["Allow"]; allow206Exists {
			if strings.Contains(req.Header["Allow"][0], "206") {
				allow206 = true
			}
		}
		_, _, _, _ = nullBody, allow206, modified, allow204

		if wrongMethod(req) {
			if *debug {
				fmt.Println("This request has a", req.Request.Method, "method which is not being analyzed")
			}
			w.WriteHeader(204, nil, false)
			return
		}

		if *debug || localDebug {
			for k, v := range req.Request.Header {
				fmt.Fprintln(os.Stderr, "key:", k, "value:", v)
			}
		}

		if strings.HasPrefix(req.Request.URL.String(), "http://") {
			if *debug {
				fmt.Println("XYZ HTTP url match:", req.Request.URL.String())
			}
			var client *http.Client
			if useTProxy && govalidator.IsIP(xClientIP) {
				tproxyClient := GlobalHTTPClients[xClientIP]
				if tproxyClient == nil {
					client = CreateTproxyHTTPClient(xClientIP)
				}
			} else {
				client = GlobalHTTPClient
			}
			newReq, err := http.NewRequest(req.Request.Method, req.Request.URL.String(), nil)
			newReq.Header = req.Request.Header
			switch {
			case newReq.Header.Get("Accept-Encoding") == "gzip":
				newReq.Header.Del("Accept-Encoding")
				if *debug {
					fmt.Println(req.Request.URL.String(), "Removed Accept-Encoding Header since it contains only gzip")
				}
			case strings.Contains(newReq.Header.Get("Accept-Encoding"), "gzip, "):
				newReq.Header.Set("Accept-Encoding", strings.Replace(newReq.Header.Get("Accept-Encoding"), "gzip, ", "", -1))
				if *debug {
					fmt.Println(req.Request.URL.String(), "Removed \"gzip, \" From Accept-Encoding Header")
				}
			case strings.Contains(newReq.Header.Get("Accept-Encoding"), ", gzip"):
				newReq.Header.Set("Accept-Encoding", strings.Replace(newReq.Header.Get("Accept-Encoding"), ", gzip", "", -1))
				if *debug {
					fmt.Println(req.Request.URL.String(), "Removed \", gzip\" From Accept-Encoding Header")
				}
			default:
				if *debug {
					fmt.Println(req.Request.URL.String(), "No gzip In Accept-Encoding Header")
				}
				// no gzip
			}
			switch {
			case newReq.Header.Get("Accept-Encoding") == "deflate":
				newReq.Header.Del("Accept-Encoding")
				if *debug {
					fmt.Println(req.Request.URL.String(), "Removed Accept-Encoding Header since it contains only deflate")
				}
			case strings.Contains(newReq.Header.Get("Accept-Encoding"), "deflate, "):
				newReq.Header.Set("Accept-Encoding", strings.Replace(newReq.Header.Get("Accept-Encoding"), "deflate, ", "", -1))
				if *debug {
					fmt.Println(req.Request.URL.String(), "Removed \"deflate, \" From Accept-Encoding Header")
				}
			case strings.Contains(newReq.Header.Get("Accept-Encoding"), ", deflate"):
				newReq.Header.Set("Accept-Encoding", strings.Replace(newReq.Header.Get("Accept-Encoding"), ", deflate", "", -1))
				if *debug {
					fmt.Println(req.Request.URL.String(), "Removed \", deflate\" From Accept-Encoding Header")
				}
			default:
				if *debug {
					fmt.Println(req.Request.URL.String(), "No deflate In Accept-Encoding Header")
				}
				// no gzip
			}
			switch {
			case newReq.Header.Get("Accept-Encoding") == "sdch":
				newReq.Header.Del("Accept-Encoding")
				if *debug {
					fmt.Println(req.Request.URL.String(), "Removed Accept-Encoding Header since it contains only sdch")
				}
			case strings.Contains(newReq.Header.Get("Accept-Encoding"), "sdch, "):
				newReq.Header.Set("Accept-Encoding", strings.Replace(newReq.Header.Get("Accept-Encoding"), "sdch, ", "", -1))
				if *debug {
					fmt.Println(req.Request.URL.String(), "Removed \"sdch, \" From Accept-Encoding Header")
				}
			case strings.Contains(newReq.Header.Get("Accept-Encoding"), ", sdch"):
				newReq.Header.Set("Accept-Encoding", strings.Replace(newReq.Header.Get("Accept-Encoding"), ", sdch", "", -1))
				if *debug {
					fmt.Println(req.Request.URL.String(), "Removed \", sdch\" From Accept-Encoding Header")
				}
			default:
				if *debug {
					fmt.Println(req.Request.URL.String(), "No sdch In Accept-Encoding Header")
				}
				// no gzip
			}

			switch {
			case newReq.Header.Get("Accept-Encoding") == "br":
				newReq.Header.Del("Accept-Encoding")
				if *debug {
					fmt.Println(req.Request.URL.String(), "Removed Accept-Encoding Header since it contains only br")
				}
			case strings.Contains(newReq.Header.Get("Accept-Encoding"), "br, "):
				newReq.Header.Set("Accept-Encoding", strings.Replace(newReq.Header.Get("Accept-Encoding"), "br, ", "", -1))
				if *debug {
					fmt.Println(req.Request.URL.String(), "Removed \"br, \" From Accept-Encoding Header")
				}
			case strings.Contains(newReq.Header.Get("Accept-Encoding"), ", br"):
				newReq.Header.Set("Accept-Encoding", strings.Replace(newReq.Header.Get("Accept-Encoding"), ", br", "", -1))
				if *debug {
					fmt.Println(req.Request.URL.String(), "Removed \", br\" From Accept-Encoding Header")
				}
			default:
				if *debug {
					fmt.Println(req.Request.URL.String(), "No rb In Accept-Encoding Header")
				}
				// no gzip
			}

			if len(newReq.Header.Get("Accept-Encoding")) < 1 {
				newReq.Header.Del("Accept-Encoding")
				if *debug {
					fmt.Println(req.Request.URL.String(), "Deleteing Accept-Encoding Header since it's empty:", newReq.Header.Get("Accept-Encoding"))
				}
			}

			if *debug {
				fmt.Println(req.Request.URL.String(), "Accept-Encoding Header:", newReq.Header.Get("Accept-Encoding"))
			}

			originalResp, err := client.Do(newReq)
			if err != nil {
				if *debug {
					fmt.Println(err)
				}
				w.WriteHeader(204, nil, false)
				return
			}

			resp := new(http.Response)
			resp.Status = originalResp.Status
			resp.StatusCode = originalResp.StatusCode
			resp.Proto = originalResp.Proto
			resp.ProtoMajor = originalResp.ProtoMajor
			resp.ProtoMinor = originalResp.ProtoMinor
			resp.Header = originalResp.Header
			if *debug {
				fmt.Println(req.Request.URL.String(), "Response Header:", resp.Header)
			}
			resp.Request = originalResp.Request
			// What if it is a CONNECT request, .. shouldn't happen
			content, err := ioutil.ReadAll(originalResp.Body)
			if err != nil {
				if *debug {
					fmt.Println("returning 204 response due to an Error reading Body response fore request:", resp.Request)
				}
				w.WriteHeader(204, nil, false)
				return
			}

			pageContent := ""

			if originalResp.Header.Get("Content-Encoding") == "gzip" || strings.Contains(originalResp.Header.Get("Content-Encoding"), "gzip ") || strings.Contains(originalResp.Header.Get("Content-Encoding"), ",gzip") {
				rdata := bytes.NewReader(content)
				r, _ := gzip.NewReader(rdata)
				s, _ := ioutil.ReadAll(r)
				pageContent = string(s)
			} else {
				pageContent = string(content)
			}
			if len(pageContent) > 0 {
				//resp.Body = ioutil.NopCloser(bytes.NewBufferString(pageContent))
				w.WriteHeader(200, resp, true)
				io.WriteString(w, pageContent)
			} else {
				w.WriteHeader(200, resp, false)
			}
			return
		}

		// What I have been using for captive portal
		//io.WriteString(w, challengePage)

		if *debug {
			fmt.Println("end of the line 204 response!.. Shouldn't happen.")
		}
		w.WriteHeader(204, nil, false)
		return
	case "RESPMOD":
		w.WriteHeader(204, nil, false)
		return
	default:
		w.WriteHeader(405, nil, false)
		if *debug || localDebug {
			fmt.Fprintln(os.Stderr, "Invalid request method")
		}
	}
}

func defaultIcap(w icap.ResponseWriter, req *icap.Request) {
	localDebug := false
	if strings.Contains(req.URL.RawQuery, "debug=1") {
		localDebug = true
	}

	h := w.Header()
	h.Set("isTag", isTag)
	h.Set("Service", "YouTube GoogleVideo Predictor ICAP serivce")

	if *debug || localDebug {
		fmt.Fprintln(os.Stderr, "Printing the full ICAP request")
		fmt.Fprintln(os.Stderr, req)
		fmt.Fprintln(os.Stderr, req.Request)
	}
	switch req.Method {
	case "OPTIONS":
		h.Set("Methods", "REQMOD, RESPMOD")
		h.Set("Options-TTL", "1800")
		h.Set("Allow", "204")
		h.Set("Preview", "0")
		h.Set("Transfer-Preview", "*")
		h.Set("Max-Connections", *maxConnections)
		h.Set("This-Server", "Default ICAP url which bypass all requests adaptation")
		h.Set("X-Include", "X-Client-IP, X-Authenticated-Groups, X-Authenticated-User, X-Subscriber-Id, X-Server-Ip, X-Store-Id")
		w.WriteHeader(200, nil, false)
	case "REQMOD":
		if *debug || localDebug {
			fmt.Fprintln(os.Stderr, "Default REQMOD, you should use the apropriate ICAP service URL")
		}
		w.WriteHeader(204, nil, false)
	case "RESPMOD":
		if *debug || localDebug {
			fmt.Fprintln(os.Stderr, "Default RESPMOD, you should use the apropriate ICAP service URL")
		}
		w.WriteHeader(204, nil, false)
	default:
		w.WriteHeader(405, nil, false)
		if *debug || localDebug {
			fmt.Fprintln(os.Stderr, "Invalid request method")
		}
	}
}

func init() {
	fmt.Fprintln(os.Stderr, "Starting YouTube GoogleVideo Predictor ICAP serivce")

	debug = flag.Bool("d", false, "Debug mode can be \"1\" or \"0\" for no")
	address = flag.String("p", "127.0.0.1:1344", "Listening address for the ICAP service")
	maxConnections = flag.String("maxcon", "4000", "Maximum number of connections for the ICAP service")
	redisAddress = flag.String("redis-address", "127.0.0.1:6379", "Redis DB address to store youtube tokens")
	upnkeyTimeout = flag.Int("cache-key-timeout", 360, "Redis or GoCache DB key timeout in Minutes")
	useGoCache = flag.Bool("Use GoCache", true, "GoCache DB is used by default and if disabled then Redis is used")

	flag.Parse()
}

func main() {
	fmt.Fprintln(os.Stderr, "running YouTube GoogleVideo Predictor ICAP serivce :D")

	if *debug {
		fmt.Fprintln(os.Stderr, "Config Variables:")
		fmt.Fprintln(os.Stderr, "Debug: => "+strconv.FormatBool(*debug))
		fmt.Fprintln(os.Stderr, "Listen Address: => "+*address)
		fmt.Fprintln(os.Stderr, "Redis DB Address: => "+*redisAddress)
		fmt.Fprintln(os.Stderr, "Maximum number of Connections: => "+*maxConnections)
	}

	if *useGoCache {
		goCacheLocal = cache.New(time.Duration(*upnkeyTimeout)*time.Minute, 10*time.Minute)
	} else {
		redisDB = *redis.NewClient(&redis.Options{
			Addr:     *redisAddress,
			Password: "", // no password set
			DB:       0,  // use default DB
		})
	}

	GlobalHTTPClient = &http.Client{}
	GlobalHTTPClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return errors.New("redirect")
	}

	icap.HandleFunc("/injectjs/", htmlJSInject)
	icap.HandleFunc("/", defaultIcap)
	log.Fatal(icap.ListenAndServe(*address, nil))
}
