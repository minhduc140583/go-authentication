package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/common-go/config"
	"github.com/gorilla/mux"

	"go-service/internal/app"
)

func main() {
	conf := app.Root{}
	config.Load(&conf, "configs/config")

	r := mux.NewRouter()
	er2 := app.Route(r, context.Background(), conf)
	if er2 != nil {
		panic(er2)
	}
	fmt.Println("Start server")
	server := ""
	if conf.Server.Port > 0 {
		server = ":" + strconv.Itoa(conf.Server.Port)
	}
	http.ListenAndServe(server, r)
}
