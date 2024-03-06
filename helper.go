package helper

import (
	"log"
	"os"
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
