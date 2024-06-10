package helper

import (
	"fmt"
	"log"
	"os"
	"strings"
)

const WrongMessage = "What are you doing here?"

type Message struct {
	Message string `json:"message"`
}

// MustGetenv validates if the environment variable is set and returns it
// otherwise it will log a fatal error and exit the program
// It is used to validate the environment variables
// Example:
//   - os.Setenv("TEST", "test")
//   - log.Println(MustGetenv("TEST"))
//   - log.Println(MustGetenv("TEST2"))
//
// Output:
//   - test
//   - 2021/08/31 11:30:00 Missing environment variable: TEST2
//   - exit status 1
func MustGetenv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalln(" Missing environment variable: ", k)
	}
	return v
}

func Logger(message string, level string) {
	var (
		project = getGCPProject()
	)

	if project != "" {
		gcpLogger(message, level, project)
	} else {
		log.Print(level + ": " + message + "\n")
	}
}

// ConvertToBoolPointer is a simple function that converts a interface to a *bool
func ConvertToBoolPointer(value interface{}) *bool {
	switch v := value.(type) {
	case *bool:
		return v
	case bool:
		return &v
	default:
		return nil
	}
}

// List2String converts a list of strings to a string in the format ["value1","value2"]
func List2String(values []string) string {
	var response strings.Builder

	response.WriteString("[")
	for i, valor := range values {
		response.WriteString(fmt.Sprintf(`"%s"`, valor))
		if i < len(values)-1 {
			response.WriteString(",")
		}
	}
	response.WriteString("]")

	return response.String()
}
