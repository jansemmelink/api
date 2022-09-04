package api

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/go-msvc/errors"
	"github.com/gorilla/mux"
	"github.com/stewelarend/logger"
)

var log = logger.New().WithLevel(logger.LevelDebug)

func New(paths map[string]interface{}) Api {
	api := &api{
		r:              mux.NewRouter(),
		middlewareList: []Middleware{},
	}
	if err := api.addPaths("", paths); err != nil {
		panic(fmt.Sprintf("cannot add specified paths: %+v", err))
	}
	return api
}

type Api interface {
	Middleware(Middleware) Api
	Run(addr string)
}

func (api *api) addPaths(parentPath string, paths map[string]interface{}) error {
	var fullPath = parentPath
	if fullPath == "" {
		fullPath = "/"
	}
	for path, value := range paths {
		switch path {
		case "POST":
			api.r.HandleFunc(fullPath, api.hdlr(value)).Methods(http.MethodPost)
			log.Debugf("%s %s", path, fullPath)
		case "GET":
			api.r.HandleFunc(fullPath, api.hdlr(value)).Methods(http.MethodGet)
			log.Debugf("%s %s", path, fullPath)
		case "PUT":
			api.r.HandleFunc(fullPath, api.hdlr(value)).Methods(http.MethodPut)
			log.Debugf("%s %s", path, fullPath)
		case "DEL":
			api.r.HandleFunc(fullPath, api.hdlr(value)).Methods(http.MethodDelete)
			log.Debugf("%s %s", path, fullPath)
		default:
			if subPaths, ok := value.(map[string]interface{}); ok {
				if err := api.addPaths(parentPath+"/"+path, subPaths); err != nil {
					return errors.Wrapf(err, "failed on %s/%s", parentPath, path)
				}
			} else {
				return errors.Errorf("invalid paths value: %s/%s:(%T)", parentPath, path, value)
			}
		}
	}
	return nil
} //addPaths()

type api struct {
	r              *mux.Router
	middlewareList []Middleware
}

type Middleware interface {
	Middleware(ctx context.Context, httpReq *http.Request) (map[interface{}]interface{}, error)
}

func (api *api) Middleware(mw Middleware) Api {
	//api.r.Use(fnc)
	api.middlewareList = append(api.middlewareList, mw)
	log.Debugf("Added middleware (now %d): %+v", len(api.middlewareList), api.middlewareList)
	return api
}

func (api *api) Run(addr string) {
	//api.Doc()

	//todo: move flags to env
	var wait time.Duration = time.Second * 15
	flag.DurationVar(&wait, "graceful-timeout", time.Second*15, "the duration for which the server gracefully wait for existing connections to finish - e.g. 15s or 1m")
	flag.Parse()

	srv := &http.Server{
		Addr: addr,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      api.CORS(api.r), // Pass our instance of gorilla/mux in.
	}

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Errorf("HTTP server failed: %+v", err)
		} else {
			log.Debug("HTTP server terminated")
		}
	}()

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	log.Infof("HTTP Server shutting down ...")
	srv.Shutdown(ctx)
	log.Infof("HTTP Server down.")

	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.
	os.Exit(0)
}

func (api *api) CORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		fmt.Printf("HTTP %s %s (origin:%s)\n", r.Method, r.URL.Path, origin)
		w.Header().Set("Access-Control-Allow-Origin", origin)
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "OPTIONS,GET,POST,PUT,DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, content-type, Accept, Authorization, Don8-Auth-Sid")
			//w.WriteHeader(http.StatusNoContent)
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

// type authRequirment int

// const (
// 	authNone authRequirment = iota
// 	// authTpw
// 	authSession
// )

type CtxParams struct{}

func (api *api) hdlr(fnc interface{}) http.HandlerFunc {
	fncType := reflect.TypeOf(fnc)
	fncValue := reflect.ValueOf(fnc)
	var reqType reflect.Type
	if fncType.NumIn() > 1 {
		reqType = fncType.In(1)
	}

	type ErrorResponse struct {
		Error string `json:"error"`
	}

	return func(httpRes http.ResponseWriter, httpReq *http.Request) {
		ctx := context.Background()
		var status int = http.StatusInternalServerError
		var err error
		var res interface{}
		defer func() {
			if err != nil {
				//log full error but in response, only log the base error
				log.Errorf("Failed: %+v\n", err)
				for {
					if baseErr, ok := err.(errors.IError); ok {
						if baseErr.Code() > 0 {
							status = baseErr.Code()
						}
						if baseErr.Parent() != nil {
							err = baseErr.Parent()
						} else {
							break
						}
					}
				}
				res = ErrorResponse{Error: fmt.Sprintf("%+s", err)}
			}
			httpRes.Header().Set("Content-Type", "application/json")
			httpRes.WriteHeader(status)
			if res != nil {
				jsonRes, _ := json.Marshal(res)
				httpRes.Write(jsonRes)
				fmt.Printf("-> %s\n", jsonRes)
			}
		}()

		//allow middleware to add to context
		log.Debugf("Calling %d middleware functions ...", len(api.middlewareList))
		for _, mw := range api.middlewareList {
			var values map[interface{}]interface{}
			values, err = mw.Middleware(ctx, httpReq)
			if err != nil {
				err = errors.Wrapf(err, "middleware failed")
				return
			}
			log.Debugf("Adding %d middleware values to context", len(values))
			for key, value := range values {
				ctx = context.WithValue(ctx, key, value)
			}
		}

		//get parameters from URL and path
		params := newParams()
		for n, v := range httpReq.URL.Query() {
			log.Debugf("URL param %s:%s", n, v)
			params = params.With(n, strings.Join(v, ","))
		}
		vars := mux.Vars(httpReq)
		for n, v := range vars {
			log.Debugf("URL path param %s:%s", n, v)
			params = params.With(n, v)
		}
		ctx = context.WithValue(ctx, CtxParams{}, params)

		//prepare fnc arguments
		args := []reflect.Value{reflect.ValueOf(ctx)}

		if fncType.NumIn() > 1 {
			//prepare the request
			reqValuePtr := reflect.New(reqType)

			//default to JSON body, or ignore if no body
			ct := httpReq.Header.Get("Content-Type")
			if ct != "" && ct != "application/json" {
				err = errors.Errorc(http.StatusBadRequest, fmt.Sprintf("invalid Content-Type: %+s, expecting application/json", ct))
				return
			}
			if err = json.NewDecoder(httpReq.Body).Decode(reqValuePtr.Interface()); err != nil && err != io.EOF {
				err = errors.Errorc(http.StatusBadRequest, fmt.Sprintf("cannot parse JSON body: %+s", err))
				return
			}

			if validator, ok := reqValuePtr.Interface().(Validator); ok {
				if err = validator.Validate(); err != nil {
					log.Errorf("Invalid (%T): %+v:  %+v", reqValuePtr.Interface(), err, reqValuePtr.Interface())
					err = errors.Errorc(http.StatusBadRequest, err.Error())
					return
				}
				log.Debugf("Validated (%T) %+v", reqValuePtr.Interface(), reqValuePtr.Interface())
			} else {
				log.Debugf("Not Validating (%T) %+v", reqValuePtr.Interface(), reqValuePtr.Interface())
			}
			args = append(args, reqValuePtr.Elem())
		}

		results := fncValue.Call(args)

		errValue := results[len(results)-1] //last result is error
		if !errValue.IsNil() {
			err = errors.Wrapf(errValue.Interface().(error), "handler failed")
			return
		}

		if fncType.NumOut() > 1 {
			if results[0].IsValid() {
				if results[0].Type().Kind() == reflect.Ptr && !results[0].IsNil() {
					res = results[0].Elem().Interface() //dereference the pointer
				} else {
					res = results[0].Interface()
				}
			}
		}

		//success: set status code
		switch httpReq.Method {
		case http.MethodPost, http.MethodPut:
			status = http.StatusAccepted
		case http.MethodGet:
			status = http.StatusOK
		case http.MethodDelete:
			status = http.StatusNoContent
			res = nil
		}
	}
}

type Validator interface {
	Validate() error
}

type Params struct {
	value map[string]string
}

func newParams() Params {
	return Params{
		value: map[string]string{},
	}
}

func (p Params) With(n, v string) Params {
	p.value[n] = v
	return p
}

func (p Params) String(n, defaultValue string) string {
	if s, ok := p.value[n]; !ok {
		return defaultValue
	} else {
		return s
	}
}

func (p Params) Int(n string, defaultValue, minValue, maxValue int) int {
	s, ok := p.value[n]
	if !ok {
		return defaultValue
	}
	i64, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return defaultValue
	}
	if int(i64) < minValue {
		return minValue
	}
	if int(i64) > maxValue {
		return maxValue
	}
	return int(i64)
}

func (api api) Doc() {
	if err := api.r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemplate, err := route.GetPathTemplate()
		if err != nil {
			pathTemplate = "/"
		}
		// pathRegexp, err := route.GetPathRegexp()
		// if err == nil {
		// 	fmt.Println("Path regexp:", pathRegexp)
		// }
		queriesTemplates, err := route.GetQueriesTemplates()
		if err == nil && len(queriesTemplates) > 0 {
			fmt.Println("Queries templates:", strings.Join(queriesTemplates, ","))
		}
		queriesRegexps, err := route.GetQueriesRegexp()
		if err == nil && len(queriesRegexps) > 0 {
			fmt.Println("Queries regexps:", strings.Join(queriesRegexps, ","))
		}
		methods, err := route.GetMethods()
		if err == nil && len(methods) > 0 {
			fmt.Println("Methods:", strings.Join(methods, ","))
		}
		fmt.Printf("ROUTE: path=%s params=%s params.regex=%s methods=%s\n",
			pathTemplate,
			//pathRegexp,
			strings.Join(queriesTemplates, ","),
			strings.Join(queriesRegexps, ","),
			strings.Join(methods, ","))
		return nil
	}); err != nil {
		panic(fmt.Sprintf("failed to walk routes: %+v", err))
	}
} //api.Doc()
