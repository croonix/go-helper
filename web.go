package helper

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func GetFavicon(w http.ResponseWriter, r *http.Request) {
	iconData, err := os.ReadFile("./favicon.ico")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println(" - Error: ", err)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Write(iconData)
}

// CatMode is a function that will print the request information
// It will print the URL, Method, Headers and Body of the request
// It is used to debug the request information
func CatMode(r *http.Request) {
	enableCatMode := os.Getenv("CAT_MODE")
	if enableCatMode == "1" && r.URL.Path != "/health" && r.URL.Path != "/favicon.ico" && r.URL.Path != "/healthz" {
		log.Println(r)
	}
}

// CheckBody is a function that will print the request information
// It will print the URL, Method, Headers and Body of the request
// It is used to debug the request information
// Needs to be used with io.TeeReader to be able to read the body multiple times
// Example:
//   - http.HandleFunc("/", CheckBody)
//
// Output:
//   - Request information:
//   - Request URL:  /?test=1
//   - Request Method:  GET
//   - Request Headers:  map[Accept:[*/*] Accept-Encoding:[gzip] User-Agent:[Go-http-client/1.1]]
//   - Request Body:  test=1
func CheckBody(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, " * Error: "+err.Error(), http.StatusBadRequest)
		return
	}
	log.Println(" -------------------------------------------------------------")
	log.Println(" Request information:")
	log.Println(" - Request URL: ", r.URL)
	log.Println(" - Request Method: ", r.Method)
	log.Println(" - Request Headers: ", r.Header)
	log.Println(" - Request Body: ", string(body))
	log.Println(" -------------------------------------------------------------")
}

func MessageHelper(w http.ResponseWriter, message string) {
	output := Message{
		Message: message,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(output)
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	message := Message{
		Message: "Thanks for checking in! I'm doing fine.",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(message)
}

func WrongParameter(w http.ResponseWriter, r *http.Request) {
	var (
		paramString string
		parameters  = r.URL.Query()
	)

	for key, values := range parameters {
		valueStr := strings.Join(values, ", ")
		paramString += fmt.Sprintf("%s:%s ", key, valueStr)
	}
	Logger(fmt.Sprintf(" - Wrong parameters were passed: [%s]", paramString), "notice")
	http.Error(w, WrongMessage, http.StatusTeapot)
}

func UndefinedAnswer(w http.ResponseWriter, r *http.Request) {
	Logger("=============================================================", "warning")
	Logger(" Wrong request with the following parameters:", "warning")
	Logger(fmt.Sprint(" - Host: ", r.Host), "warning")
	Logger(fmt.Sprint(" - Method: ", r.Method), "warning")
	Logger(fmt.Sprint(" - Protocol: ", r.Proto), "warning")
	Logger(fmt.Sprint(" - RequestURI: ", r.RequestURI), "warning")
	Logger(fmt.Sprint(" - RemoteAddr: ", r.RemoteAddr), "warning")
	Logger("=============================================================", "warning")
	http.Error(w, WrongMessage, http.StatusTeapot)
}

func WrongPath() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		Logger("=============================================================", "warning")
		Logger(" Wrong request with the following parameters:", "warning")
		Logger(fmt.Sprint(" - Host: ", r.Host), "warning")
		Logger(fmt.Sprint(" - Method: ", r.Method), "warning")
		Logger(fmt.Sprint(" - Protocol: ", r.Proto), "warning")
		Logger(fmt.Sprint(" - RequestURI: ", r.RequestURI), "warning")
		Logger(fmt.Sprint(" - RemoteAddr: ", r.RemoteAddr), "warning")
		Logger("=============================================================", "warning")
		http.Error(w, WrongMessage, http.StatusTeapot)
	})
}
