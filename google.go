package helper

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"time"

	"cloud.google.com/go/logging"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

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
