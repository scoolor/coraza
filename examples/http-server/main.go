package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

func exampleHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	resBody := "Hello world, transaction not disrupted."

	if body := os.Getenv("RESPONSE_BODY"); body != "" {
		resBody = body
	}

	if h := os.Getenv("RESPONSE_HEADERS"); h != "" {
		key, val, _ := strings.Cut(h, ":")
		w.Header().Set(key, val)
	}

	// The server generates the response
	w.Write([]byte(resBody))
}

func main() {
	waf := createWAF()

	http.Handle("/", txhttp.WrapHandler(waf, http.HandlerFunc(exampleHandler)))

	fmt.Println("Server is running. Listening port: 8090")

	log.Fatal(http.ListenAndServe(":8090", nil))
}

func createWAF() coraza.WAF {

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(logError).
			WithDirectivesFromFile("./coreruleset/coraza.conf").
			WithDirectivesFromFile("./coreruleset/crs-setup.conf").
			WithDirectivesFromFile("./coreruleset/rules/*.conf"),
	)
	if err != nil {
		log.Fatal(err)
	}
	return waf
}

func logError(error types.MatchedRule) {
	msg := error.ErrorLog()
	fmt.Printf("[logError][%s] %s\n", error.Rule().Severity(), msg)
}
