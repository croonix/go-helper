package helper

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"cloud.google.com/go/logging"
)

const WrongMessage = "What are you doing here?"

func MustGetenv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalln(" Missing environment variable: ", k)
	}
	return v
}

func getLoggerProject() string {
	var (
		url       = "http://metadata.google.internal/computeMetadata/v1/project/project-id"
		projectID string
	)

	webRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalln(" Something went wrong at logger project request:\n", err)
	}

	webRequest.Header.Add("Metadata-Flavor", "Google")
	webClient := &http.Client{}
	webResponse, err := webClient.Do(webRequest)
	if err != nil {
		log.Fatalln(" Something went wrong at logger project response:\n", err)
	}
	defer webResponse.Body.Close()

	if webResponse.StatusCode == http.StatusOK {
		webBody, err := io.ReadAll(webResponse.Body)
		if err != nil {
			log.Fatalln(" Something went wrong at logger project body:\n", err)
		}
		projectID = string(webBody)
	} else {
		log.Fatalln(" Something went wrong at logger project status:\n", webResponse.StatusCode)
	}
	return projectID
}

func Logger(message string, level string) {
	var (
		ctx      = context.Background()
		project  = getLoggerProject()
		severity = logging.Default
	)

	switch level {
	case "info":
		severity = logging.Info
	case "notice":
		severity = logging.Notice
	case "warning":
		severity = logging.Warning
	case "error":
		severity = logging.Error
	case "critical":
		severity = logging.Critical
	default:
		severity = logging.Default
	}

	loggingClient, err := logging.NewClient(ctx, project)
	if err != nil {
		log.Fatalln(" Something went wrong at logger client:\n", err)
	}
	defer loggingClient.Close()

	logger := loggingClient.Logger("run.googleapis.com/patching-service")
	loggerFromTemplate := logger.StandardLoggerFromTemplate(&logging.Entry{
		Severity: severity,
	})
	loggerFromTemplate.Print(message)
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"message": "Thanks for checking in! I'm doing fine."}`))
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
