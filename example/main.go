package main

import (
	"context"

	"github.com/go-msvc/errors"
	"github.com/jansemmelink/api"
)

func main() {
	paths := map[string]interface{}{
		"GET":     health,
		"auth":    authRoutes(),
		"product": productRoutes(),
	}
	api.New(paths).Run(":8080")
}

func authRoutes() interface{} {
	return map[string]interface{}{
		"register": map[string]interface{}{"POST": register},
		"activate": map[string]interface{}{"POST": activate},
		"reset":    map[string]interface{}{"POST": reset},
		"login":    map[string]interface{}{"POST": login},
		"logout":   map[string]interface{}{"POST": logout},
	}
}

func productRoutes() interface{} {
	return map[string]interface{}{
		"GET":  listProducts,
		"POST": addProduct,
		"{id}": map[string]interface{}{
			"GET": getProduct,
			"PUT": updProduct,
			"DEL": delProduct,
		},
	}
}

func health(ctx context.Context) error       { return errors.Errorf("NYI") }
func register(ctx context.Context) error     { return errors.Errorf("NYI") }
func activate(ctx context.Context) error     { return errors.Errorf("NYI") }
func reset(ctx context.Context) error        { return errors.Errorf("NYI") }
func login(ctx context.Context) error        { return errors.Errorf("NYI") }
func logout(ctx context.Context) error       { return errors.Errorf("NYI") }
func listProducts(ctx context.Context) error { return errors.Errorf("NYI") }
func addProduct(ctx context.Context) error   { return errors.Errorf("NYI") }
func getProduct(ctx context.Context) error   { return errors.Errorf("NYI") }
func updProduct(ctx context.Context) error   { return errors.Errorf("NYI") }
func delProduct(ctx context.Context) error   { return errors.Errorf("NYI") }
