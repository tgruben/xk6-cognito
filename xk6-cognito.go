package cognito

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cipTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

	// "go.k6.io/k6/js/common"
	"go.k6.io/k6/js/modules"
)

// Register the extension on module initialization, available to
// import from JS as "k6/x/cognito".
func init() {
	modules.Register("k6/x/cognito", new(Cognito))
}

// Cognito is the k6 extension for a Cognito client.
type Cognito struct{}

// Client is the Cognito client wrapper.
type Client struct {
	ctx context.Context
	// https://github.com/aws/aws-sdk-go-v2/blob/main/service/cognitoidentityprovider/api_client.go
	client *cip.Client
}
type keyValue map[string]interface{}

type AuthOptionalParams struct {
	// https://stackoverflow.com/questions/2032149/optional-parameters-in-go
	clientMetadata map[string]string
	cognitoSecret  *string
}

func contains(array []string, element string) bool {
	for _, item := range array {
		if item == element {
			return true
		}
	}
	return false
}

func (r *Cognito) Connect(region string) (*Client, error) {
	regionAws := config.WithRegion(region)
	// cred := config.WithCredentialsProvider(aws.AnonymousCredentials{})

	// configure cognito identity provider
	// https://github.com/aws/aws-sdk-go-v2
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		regionAws,
	)
	if err != nil {
		return nil, err
	}

	client := Client{
		ctx:    context.TODO(),
		client: cip.NewFromConfig(cfg),
	}

	return &client, nil
}

func (c *Client) Auth(username string, password string, clientId string) (keyValue, error) {

	// initiate auth
	input := &cip.InitiateAuthInput{
		AuthFlow: cipTypes.AuthFlowTypeUserPasswordAuth,
		AuthParameters: map[string]string{
			"USERNAME": username,
			"PASSWORD": password,
		},
		ClientId: &clientId,
	}

	// Call Cognito to initiate auth
	resp, err := c.client.InitiateAuth(context.TODO(), input)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate auth: %v", err)
	}

	if resp.AuthenticationResult == nil {
		return nil, fmt.Errorf("authentication result was nil, check if the flow is correct or if additional challenges are required")
	}

	data := keyValue{
		"AccessToken":  *resp.AuthenticationResult.AccessToken,
		"IdToken":      *resp.AuthenticationResult.IdToken,
		"RefreshToken": *resp.AuthenticationResult.RefreshToken,
	}

	return data, nil

}
