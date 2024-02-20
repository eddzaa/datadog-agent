package azureutils

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4"
	"github.com/DataDog/datadog-agent/cmd/agentless-scanner/types"
	ddogstatsd "github.com/DataDog/datadog-go/v5/statsd"
	"net/http"
	"sync"
)

var (
	statsd *ddogstatsd.Client

	// TODO
	globalConfigs   sync.Map
	globalConfigsMu sync.Mutex
)

// A Config provides service configuration for service clients.
type Config struct {
	// The credentials object to use when signing requests.
	Credentials azcore.TokenCredential

	// The HTTP Client the SDK's API clients will use to invoke HTTP requests.
	HTTPClient *http.Client

	ComputeClientFactory *armcompute.ClientFactory

	// The subscription ID of the agentless scanner
	ScannerSubscription string

	// The location of the agentless scanner
	ScannerLocation string

	// The resource group used by resources created for and by the scanner
	ScannerResourceGroup string
}

func GetConfigFromCloudID(ctx context.Context, cloudID types.CloudID) (Config, error) {
	resourceID, err := cloudID.AsAzureID()
	if err != nil {
		return Config{}, err
	}

	return GetConfig(ctx, resourceID.SubscriptionID)
}

func GetConfig(ctx context.Context, subscriptionID string) (Config, error) {
	globalConfigsMu.Lock()
	defer globalConfigsMu.Unlock()

	if statsd == nil {
		statsd, _ = ddogstatsd.New("localhost:8125")
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return Config{}, err
	}

	metadata, err := GetInstanceMetadata(ctx)
	if err != nil {
		return Config{}, err
	}

	computeClientFactory, err := armcompute.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		return Config{}, err
	}

	return Config{
		Credentials:          cred,
		ComputeClientFactory: computeClientFactory,
		ScannerSubscription:  metadata.Compute.SubscriptionID,
		ScannerLocation:      metadata.Compute.Location,
		ScannerResourceGroup: metadata.Compute.ResourceGroupName,
	}, nil
}
