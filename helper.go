package helper

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/logging"
	"github.com/go-sql-driver/mysql"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

const WrongMessage = "What are you doing here?"

type Message struct {
	Message string `json:"message"`
}

func GetFavicon(w http.ResponseWriter, r *http.Request) {
	iconData, err := os.ReadFile("./favicon.ico")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		fmt.Println(" - Error: ", err)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Write(iconData)
}

// MustGetenv validates if the environment variable is set and returns it
// otherwise it will log a fatal error and exit the program
// It is used to validate the environment variables
// Example:
//   - os.Setenv("TEST", "test")
//   - fmt.Println(MustGetenv("TEST"))
//   - fmt.Println(MustGetenv("TEST2"))
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

func ImpersonateSA(context context.Context, serviceAccount string, scope string) (token oauth2.TokenSource, err error) {
	credentials, err := google.FindDefaultCredentials(context, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		Logger(fmt.Sprint(" Failed to find the default credentials:", err), "critical")
		return
	}

	token, err = impersonate.CredentialsTokenSource(context, impersonate.CredentialsConfig{
		TargetPrincipal: serviceAccount,
		Scopes:          []string{"https://www.googleapis.com/auth/iam", scope},
		Lifetime:        300 * time.Second,
		Delegates:       []string{},
	}, option.WithCredentials(credentials))
	if err != nil {
		Logger(fmt.Sprint(" Failed to CredentialsTokenSource: ", err), "critical")
		return
	}
	return token, nil
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

func AddServiceAccountUserRole(impersonateAccount string, targetAccount string, principalAccount string) error {
	return setServiceAccountUserRole(impersonateAccount, targetAccount, principalAccount, true)
}

func RemoveServiceAccountUserRole(impersonateAccount string, targetAccount string, principalAccount string) error {
	return setServiceAccountUserRole(impersonateAccount, targetAccount, principalAccount, false)
}

func setServiceAccountUserRole(impersonateAccount string, targetAccount string, principalAccount string, enabled bool) error {
	var (
		ctx           = context.Background()
		functionScope = "https://www.googleapis.com/auth/iam"
		principalId   = fmt.Sprintf("serviceAccount:%s", principalAccount)
		targetId      = fmt.Sprintf("projects/%s/serviceAccounts/%s", GetProjectFromServiceAccount(targetAccount), targetAccount)
		role          = "roles/iam.serviceAccountUser"
		iamClient     *iam.Service
		token         oauth2.TokenSource
	)

	if impersonateAccount != "" {
		var err error
		token, err = ImpersonateSA(ctx, impersonateAccount, functionScope)
		if err != nil {
			return err
		}

		iamClient, err = iam.NewService(ctx, option.WithTokenSource(token))
		if err != nil {
			return err
		}
	} else {
		var err error
		iamClient, err = iam.NewService(ctx)
		if err != nil {
			return err
		}
	}

	currentPolicy, err := iamClient.Projects.ServiceAccounts.GetIamPolicy(targetId).Do()
	if err != nil {
		return err
	}

	if enabled {
		newBinding := &iam.Binding{
			Role:    role,
			Members: []string{principalId},
		}

		_, err = iamClient.Projects.ServiceAccounts.SetIamPolicy(targetId, &iam.SetIamPolicyRequest{
			Policy: &iam.Policy{
				Bindings: append(currentPolicy.Bindings, newBinding),
			},
		}).Do()
		if err != nil {
			return err
		}
		return nil
	} else {
		var updatedBindings []*iam.Binding
		for _, binding := range currentPolicy.Bindings {
			if binding.Role != role {
				updatedBindings = append(updatedBindings, &iam.Binding{
					Role:    binding.Role,
					Members: binding.Members,
				})
				continue
			}
			var membersWithoutUser []string
			for _, member := range binding.Members {
				if member != principalId {
					membersWithoutUser = append(membersWithoutUser, member)
					updatedBindings = append(updatedBindings, &iam.Binding{
						Role:    binding.Role,
						Members: membersWithoutUser,
					})
				}
			}
		}
		_, err = iamClient.Projects.ServiceAccounts.SetIamPolicy(targetId, &iam.SetIamPolicyRequest{
			Policy: &iam.Policy{
				Bindings: updatedBindings,
			},
		}).Do()
		if err != nil {
			return err
		}
		return nil
	}
}

func GetProjectFromServiceAccount(serviceAccount string) string {
	regex := regexp.MustCompile(`@([^\.]+)\.iam\.gserviceaccount\.com`)
	matches := regex.FindStringSubmatch(serviceAccount)

	if len(matches) >= 2 {
		return matches[1]
	} else {
		return "-"
	}
}

func getGCPProject() string {
	var (
		url       = "http://metadata.google.internal/computeMetadata/v1/project/project-id"
		projectID string
	)

	webRequest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}

	webRequest.Header.Add("Metadata-Flavor", "Google")
	webClient := &http.Client{}
	webResponse, err := webClient.Do(webRequest)
	if err != nil {
		return ""
	}
	defer webResponse.Body.Close()

	if webResponse.StatusCode == http.StatusOK {
		webBody, err := io.ReadAll(webResponse.Body)
		if err != nil {
			return ""
		}
		projectID = string(webBody)
	} else {
		return ""
	}

	return projectID
}

func gcpLogger(message string, level string, project string) {
	var (
		ctx = context.Background()
	)

	severity := logging.ParseSeverity(level)

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

func Logger(message string, level string) {
	var (
		project = getGCPProject()
	)

	if project != "" {
		gcpLogger(message, level, project)
	} else {
		fmt.Print(level + ": " + message + "\n")
	}
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

func ConnectCloudSQL(database string) *sql.DB {
	databaseSocket, err := connectTCPSocket(database)
	if err != nil {
		Logger(fmt.Sprint(" Something went wrong when trying to create a connection to the database: ", err), "critical")
		return nil
	}

	if databaseSocket == nil {
		Logger(" Something went wrong with the values that were passed to the database connection.", "critical")
		return nil
	}

	return databaseSocket
}

func connectTCPSocket(database string) (*sql.DB, error) {
	var (
		databaseUser     = MustGetenv("DATABASE_USER")
		databasePassword = MustGetenv("DATABASE_PASS")
		databaseIP       = MustGetenv("DATABASE_IP")
		databaseName     = MustGetenv("DATABASE_NAME")
		databaseProject  = MustGetenv("PROJECT_ID")
		databasePort     = "3306"
	)

	databaseURI := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", databaseUser, databasePassword, databaseIP, databasePort, database)

	if databaseRootCert, ok := os.LookupEnv("DATABASE_ROOT_CERT"); ok {
		var (
			databaseCert    = MustGetenv("DATABASE_CERT")
			databaseCertKey = MustGetenv("DATABASE_CERT_KEY")
		)
		certificatePool := x509.NewCertPool()
		rootCertificate, err := os.ReadFile(databaseRootCert)
		if err != nil {
			Logger(fmt.Sprint(" Something went wrong when trying to read the root certificate: ", err), "critical")
			return nil, err
		}

		if ok := certificatePool.AppendCertsFromPEM(rootCertificate); !ok {
			Logger(fmt.Sprint(" Something went wrong when trying to append the root certificate to the pool: ", err), "critical")
			return nil, errors.New("unable to append root cert to pool")
		}

		clientCertificate, err := tls.LoadX509KeyPair(databaseCert, databaseCertKey)
		if err != nil {
			Logger(fmt.Sprint(" Something went wrong when trying to load the client certificate: ", err), "critical")
			return nil, err
		}

		// Issue with the connection and use the function in here:
		// https://github.com/golang/go/issues/40748
		mysql.RegisterTLSConfig("cloudsql", &tls.Config{
			RootCAs:            certificatePool,
			Certificates:       []tls.Certificate{clientCertificate},
			InsecureSkipVerify: true,
			ServerName:         databaseProject + ":" + databaseName,
			VerifyConnection: func(cs tls.ConnectionState) error {
				commonName := cs.PeerCertificates[0].Subject.CommonName
				if commonName != cs.ServerName {
					Logger(fmt.Sprintf(" Something went wrong when trying to verify the connection: invalid certificate name %q, expected %q", commonName, cs.ServerName), "critical")
					return fmt.Errorf(" Something went wrong when trying to verify the connection: invalid certificate name")
				}
				opts := x509.VerifyOptions{
					Roots:         certificatePool,
					Intermediates: x509.NewCertPool(),
				}
				for _, cert := range cs.PeerCertificates[1:] {
					opts.Intermediates.AddCert(cert)
				}
				_, err := cs.PeerCertificates[0].Verify(opts)
				return err
			},
		})
		databaseURI += "&tls=cloudsql"
	}

	databaseConnection, err := sql.Open("mysql", databaseURI)
	if err != nil {
		return nil, fmt.Errorf("sql.Open: %w", err)
	}

	configureConnectionPool(databaseConnection)

	return databaseConnection, nil
}

func configureConnectionPool(db *sql.DB) {
	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(7)
	db.SetConnMaxLifetime(1800 * time.Second)
}
