package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	// DataDog agent: config stuffs
	"github.com/DataDog/datadog-agent/cmd/agent/common"
	commonpath "github.com/DataDog/datadog-agent/cmd/agent/common/path"
	"github.com/DataDog/datadog-agent/cmd/internal/runcmd"
	"github.com/DataDog/datadog-agent/comp/core/config"
	"github.com/DataDog/datadog-agent/comp/core/log"
	pkgconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"github.com/DataDog/datadog-agent/pkg/version"
	"go.uber.org/fx"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/lambda"

	// DataDog agent: SBOM + proto stuffs
	sbommodel "github.com/DataDog/agent-payload/v5/sbom"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	// DataDog agent: RC stuffs
	"github.com/DataDog/datadog-agent/pkg/config/remote"
	"github.com/DataDog/datadog-agent/pkg/remoteconfig/state"

	// DataDog agent: logs stuffs
	"github.com/DataDog/datadog-agent/pkg/epforwarder"
	"github.com/DataDog/datadog-agent/pkg/logs/message"

	// DataDog agent: metrics Statsd
	ddgostatsd "github.com/DataDog/datadog-go/v5/statsd"

	// Trivy stuffs
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	local2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/vm"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"

	"github.com/spf13/cobra"
)

var (
	globalParams struct {
		ConfigFilePath string
	}
)

func main() {
	flavor.SetFlavor(flavor.SideScannerAgent)
	os.Exit(runcmd.Run(rootCommand()))
}

func rootCommand() *cobra.Command {
	sideScannerCmd := &cobra.Command{
		Use:          "side-scanner [command]",
		Short:        "Datadog Side Scanner at your service.",
		Long:         `Datadog Side Scanner scans your cloud environment for vulnerabilities, compliance and security issues.`,
		SilenceUsage: true,
	}

	sideScannerCmd.AddCommand(runCommand())
	sideScannerCmd.AddCommand(scanCommand())

	return sideScannerCmd
}

func runCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Runs the side-scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(run,
				fx.Supply(config.NewAgentParamsWithSecrets(path.Join(commonpath.DefaultConfPath, "side-scanner.yaml"))),
				fx.Supply(log.ForDaemon("SIDESCANNER", "log_file", pkgconfig.DefaultSideScannerLogFile)),
				log.Module,
				config.Module,
			)
		},
	}
}

func scanCommand() *cobra.Command {
	var cliArgs struct {
		ScanType string
		RawScan  string
	}
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "execute a scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fxutil.OneShot(
				func(log log.Component, config config.Component) error {
					return scan(log, config, cliArgs.ScanType, []byte(cliArgs.RawScan))
				},
				fx.Supply(config.NewAgentParamsWithSecrets(path.Join(commonpath.DefaultConfPath, "side-scanner.yaml"))),
				fx.Supply(log.ForDaemon("SIDESCANNER", "log_file", pkgconfig.DefaultSideScannerLogFile)),
				log.Module,
				config.Module,
			)
		},
	}

	cmd.Flags().StringVarP(&cliArgs.ScanType, "scan-type", "", "", "specify the type of scan (ebs-scan or lambda-scan)")
	cmd.Flags().StringVarP(&cliArgs.RawScan, "raw-scan-data", "", "", "scan data in JSON")

	cmd.MarkFlagRequired("scan-type")
	cmd.MarkFlagRequired("raw-scan-data")
	return cmd
}

func run(log log.Component, _ config.Component) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	common.SetupInternalProfiling(pkgconfig.Datadog, "")

	hostname, err := utils.GetHostname()
	if err != nil {
		return fmt.Errorf("could not fetch hostname: %w", err)
	}

	rcClient, err := remote.NewUnverifiedGRPCClient("sidescanner", version.AgentVersion, nil, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not init Remote Config client: %w", err)
	}

	// Create a statsd Client
	statsdAddr := os.Getenv("STATSD_URL")
	if statsdAddr == "" {
		// Retrieve statsd host and port from the datadog agent configuration file
		statsdHost := pkgconfig.GetBindHost()
		statsdPort := pkgconfig.Datadog.GetInt("dogstatsd_port")
		statsdAddr = fmt.Sprintf("%s:%d", statsdHost, statsdPort)
	}

	statsd, err := ddgostatsd.New(statsdAddr)
	if err != nil {
		return fmt.Errorf("could not init statsd client: %w", err)
	}

	scanner := newSideScanner(hostname, statsd, log, rcClient)
	scanner.start(ctx)
	return nil
}

func scan(log log.Component, _ config.Component, scanType string, rawScan []byte) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	common.SetupInternalProfiling(pkgconfig.Datadog, "")

	hostname, err := utils.GetHostname()
	if err != nil {
		return fmt.Errorf("could not fetch hostname: %w", err)
	}

	// Create a statsd Client
	statsdAddr := os.Getenv("STATSD_URL")
	if statsdAddr == "" {
		// Retrieve statsd host and port from the datadog agent configuration file
		statsdHost := pkgconfig.GetBindHost()
		statsdPort := pkgconfig.Datadog.GetInt("dogstatsd_port")
		statsdAddr = fmt.Sprintf("%s:%d", statsdHost, statsdPort)
	}

	statsd, err := ddgostatsd.New(statsdAddr)
	if err != nil {
		return fmt.Errorf("could not init statsd client: %w", err)
	}

	entity, err := launchScan(ctx, log, statsd, hostname, scanType, rawScan)
	if err != nil {
		return err
	}
	fmt.Println(entity)
	return nil
}

type scanTasks struct {
	Type     string            `json:"type"`
	RawScans []json.RawMessage `json:"scans"`
}

type scanTask struct {
	Type    string          `json:"type"`
	RawScan json.RawMessage `json:"scans"`
}

type ebsScan struct {
	Region     string `json:"region"`
	SnapshotID string `json:"snapshotId"`
	VolumeID   string `json:"volumeId"`
	Hostname   string `json:"hostname"`
}

func (s ebsScan) String() string {
	return fmt.Sprintf("region=%q snapshot_id=%q volume_id=%q hostname=%q",
		s.Region,
		s.SnapshotID,
		s.VolumeID,
		s.Hostname)
}

type lambdaScan struct {
	Region       string `json:"region"`
	FunctionName string `json:"function_name"`
}

func (s lambdaScan) String() string {
	return fmt.Sprintf("region=%q function_name=%q",
		s.Region,
		s.FunctionName)
}

type sideScanner struct {
	hostname       string
	statsd         ddgostatsd.ClientInterface
	log            log.Component
	rcClient       *remote.Client
	eventForwarder epforwarder.EventPlatformForwarder
}

func newSideScanner(hostname string, statsd ddgostatsd.ClientInterface, log log.Component, rcClient *remote.Client) *sideScanner {
	eventForwarder := epforwarder.NewEventPlatformForwarder()
	return &sideScanner{
		hostname:       hostname,
		statsd:         statsd,
		log:            log,
		rcClient:       rcClient,
		eventForwarder: eventForwarder,
	}
}

func (s *sideScanner) start(ctx context.Context) {
	s.log.Infof("Starting side-scanner with hostname %s", s.hostname)

	s.eventForwarder.Start()
	defer s.eventForwarder.Stop()

	s.rcClient.Start()
	defer s.rcClient.Close()

	scansCh := make(chan scanTask)
	s.rcClient.Subscribe(state.ProductDebug, func(update map[string]state.RawConfig, _ func(string, state.ApplyStatus)) {
		for _, cfg := range update {
			s.log.Debugf("received new task from remote-config: %s", cfg.Metadata.ID)
			var task scanTasks
			err := json.Unmarshal(cfg.Config, &task)
			if err != nil {
				s.log.Errorf("could not parse side-scanner task: %w", err)
				return
			}
			for _, rawScan := range task.RawScans {
				select {
				case <-ctx.Done():
					return
				case scansCh <- scanTask{task.Type, rawScan}:
				}
			}
		}
	})

	var wg sync.WaitGroup

	const workerPoolSize = 10
	for i := 0; i < workerPoolSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for scan := range scansCh {
				entity, err := launchScan(ctx, s.log, s.statsd, s.hostname, scan.Type, scan.RawScan)
				if err != nil {
					s.log.Errorf("error scanning task: %s", err)
				} else {
					s.sendSBOM(entity)
				}
			}
		}()
	}

	<-ctx.Done()
	close(scansCh)
	wg.Wait()
}

func (s *sideScanner) sendSBOM(entity *sbommodel.SBOMEntity) error {
	sourceAgent := "sidescanner"
	envVarEnv := pkgconfig.Datadog.GetString("env")

	rawEvent, err := proto.Marshal(&sbommodel.SBOMPayload{
		Version:  1,
		Source:   &sourceAgent,
		Entities: []*sbommodel.SBOMEntity{entity},
		DdEnv:    &envVarEnv,
	})
	if err != nil {
		return fmt.Errorf("unable to proto marhsal sbom: %w", err)
	}

	m := &message.Message{Content: rawEvent}
	return s.eventForwarder.SendEventPlatformEvent(m, epforwarder.EventTypeContainerSBOM)
}

func launchScan(ctx context.Context, log log.Component, statsd ddgostatsd.ClientInterface, hostname string, scanType string, rawScan []byte) (*sbommodel.SBOMEntity, error) {
	switch scanType {
	case "ebs-scan":
		var scan ebsScan
		if err := json.Unmarshal(rawScan, &scan); err != nil {
			return nil, err
		}
		defer log.Debugf("finished ebs-scan of %s", scan)
		return scanEBS(ctx, log, statsd, hostname, &scan)
	case "lambda-scan":
		var scan lambdaScan
		if err := json.Unmarshal(rawScan, &scan); err != nil {
			return nil, err
		}
		defer log.Debugf("finished lambda-scan of %s", scan)
		return scanLambda(ctx, log, statsd, hostname, &scan)
	default:
		return nil, fmt.Errorf("unknown scan type: %s", scanType)
	}
}

func createEBSSnapshot(ctx context.Context, svc *ec2.EC2, scan *ebsScan) (string, error) {
	result, err := svc.CreateSnapshotWithContext(ctx, &ec2.CreateSnapshotInput{
		VolumeId: aws.String(scan.VolumeID),
	})
	if err != nil {
		return "", err
	}
	err = svc.WaitUntilSnapshotCompletedWithContext(ctx, &ec2.DescribeSnapshotsInput{
		SnapshotIds: []*string{result.SnapshotId},
	})
	if err != nil {
		return "", err
	}
	return *result.SnapshotId, nil
}

func deleteEBSSnapshot(ctx context.Context, svc *ec2.EC2, snapshotID string) error {
	_, err := svc.DeleteSnapshotWithContext(ctx, &ec2.DeleteSnapshotInput{
		SnapshotId: &snapshotID,
	})
	return err
}

func scanEBS(ctx context.Context, log log.Component, statsd ddgostatsd.ClientInterface, hostname string, scan *ebsScan) (*sbommodel.SBOMEntity, error) {
	if scan.Region == "" {
		return nil, fmt.Errorf("ebs-scan: missing region")
	}
	if scan.Hostname == "" {
		return nil, fmt.Errorf("ebs-scan: missing hostname")
	}

	defer statsd.Flush()

	tags := []string{
		fmt.Sprintf("region:%s", scan.Region),
		fmt.Sprintf("type:%s", "ebs-scan"),
		fmt.Sprintf("host:%s", hostname),
	}

	snapshotID := scan.SnapshotID
	if snapshotID == "" {
		if scan.VolumeID == "" {
			return nil, fmt.Errorf("ebs-scan: missing volume ID")
		}
		snapshotStartedAt := time.Now()
		sess, err := session.NewSession(&aws.Config{
			Region: aws.String(scan.Region),
		})
		if err != nil {
			return nil, err
		}
		svc := ec2.New(sess)
		statsd.Count("datadog.sidescanner.snapshotstarted", 1.0, tags, 1.0)
		log.Debugf("starting volume snapshotting %q", scan.VolumeID)
		snapshotID, err = createEBSSnapshot(ctx, svc, scan)
		if err != nil {
			return nil, err
		}
		log.Debugf("volume snapshotting finished sucessfully %q", snapshotID)
		statsd.Count("datadog.sidescanner.snapshots.finished", 1.0, tags, 1.0)
		statsd.Histogram("datadog.sidescanner.snapshots.duration", float64(time.Since(snapshotStartedAt).Milliseconds()), tags, 1.0)
		defer func() {
			log.Debugf("deleting snapshot %q", snapshotID)
			deleteEBSSnapshot(ctx, svc, snapshotID)
		}()
	}

	log.Infof("start EBS scanning %s", scan)
	statsd.Count("datadog.sidescanner.scanstarted", 1.0, tags, 1.0)
	scanStartedAt := time.Now()
	target := "ebs:" + scan.SnapshotID
	trivyCache := newMemoryCache()
	trivyDisabledAnalyzers := []analyzer.Type{analyzer.TypeSecret, analyzer.TypeLicenseFile}
	trivyDisabledAnalyzers = append(trivyDisabledAnalyzers, analyzer.TypeConfigFiles...)
	trivyDisabledAnalyzers = append(trivyDisabledAnalyzers, analyzer.TypeLanguages...)
	trivyVMArtifact, err := vm.NewArtifact(target, trivyCache, artifact.Option{
		Offline:           true,
		NoProgress:        true,
		DisabledAnalyzers: trivyDisabledAnalyzers,
		Slow:              true,
		SBOMSources:       []string{},
		DisabledHandlers:  []ftypes.HandlerType{ftypes.UnpackagedPostHandler},
		OnlyDirs:          []string{"etc", "var/lib/dpkg", "var/lib/rpm", "lib/apk"},
		AWSRegion:         scan.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create artifact from image: %w", err)
	}
	trivyDetector := ospkg.Detector{}
	trivyVulnClient := vulnerability.NewClient(db.Config{})
	trivyApplier := applier.NewApplier(trivyCache)
	trivyLocalScanner := local.NewScanner(trivyApplier, trivyDetector, trivyVulnClient)
	trivyScanner := scanner.NewScanner(trivyLocalScanner, trivyVMArtifact)
	trivyReport, err := trivyScanner.ScanArtifact(ctx, types.ScanOptions{
		VulnType:            []string{},
		SecurityChecks:      []string{},
		ScanRemovedPackages: false,
		ListAllPackages:     true,
	})
	statsd.Count("datadog.sidescanner.scans.finished", 1.0, tags, 1.0)
	statsd.Histogram("datadog.sidescanner.scans.duration", float64(time.Since(scanStartedAt).Milliseconds()), tags, 1.0)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal report to sbom format: %w", err)
	}

	createdAt := time.Now()
	duration := time.Since(scanStartedAt)
	marshaler := cyclonedx.NewMarshaler("")
	bom, err := marshaler.Marshal(trivyReport)
	if err != nil {
		return nil, err
	}

	entity := &sbommodel.SBOMEntity{
		Status:             sbommodel.SBOMStatus_SUCCESS,
		Type:               sbommodel.SBOMSourceType_HOST_FILE_SYSTEM, // TODO: SBOMSourceType_EBS
		Id:                 scan.Hostname,
		InUse:              true,
		GeneratedAt:        timestamppb.New(createdAt),
		GenerationDuration: convertDuration(duration),
		Hash:               "",
		Sbom: &sbommodel.SBOMEntity_Cyclonedx{
			Cyclonedx: convertBOM(bom),
		},
	}

	return entity, nil
}

func scanLambda(ctx context.Context, log log.Component, statsd ddgostatsd.ClientInterface, hostname string, scan *lambdaScan) (*sbommodel.SBOMEntity, error) {
	if scan.Region == "" {
		return nil, fmt.Errorf("ebs-scan: missing region")
	}
	if scan.FunctionName == "" {
		return nil, fmt.Errorf("ebs-scan: missing function name")
	}

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(scan.Region),
	})
	if err != nil {
		return nil, err
	}
	svc := lambda.New(sess)
	lambdaFunc, err := svc.GetFunctionWithContext(ctx, &lambda.GetFunctionInput{
		FunctionName: aws.String(scan.FunctionName),
	})
	if err != nil {
		return nil, err
	}

	tempDir, err := os.MkdirTemp("", "zipPath")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	archivePath := filepath.Join(tempDir, "code.zip")
	archiveFile, err := os.Create(archivePath)
	if err != nil {
		return nil, err
	}
	defer archiveFile.Close()

	lambdaURL := *lambdaFunc.Code.Location
	resp, err := http.Get(lambdaURL) // TODO: create an http.Client with sane defaults
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	_, err = io.Copy(archiveFile, resp.Body)
	if err != nil {
		return nil, err
	}

	extractedPath := filepath.Join(tempDir, "extract")
	err = os.Mkdir(extractedPath, 0700)
	if err != nil {
		return nil, err
	}

	err = extractZip(archivePath, extractedPath)
	if err != nil {
		return nil, err
	}

	scanStartedAt := time.Now()
	trivyCache := newMemoryCache()
	trivyFSArtifact, err := local2.NewArtifact(extractedPath, trivyCache, artifact.Option{
		Offline:           true,
		NoProgress:        true,
		DisabledAnalyzers: []analyzer.Type{},
		Slow:              true,
		SBOMSources:       []string{},
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create artifact from fs: %w", err)
	}

	trivyDetector := ospkg.Detector{}
	trivyVulnClient := vulnerability.NewClient(db.Config{})
	trivyApplier := applier.NewApplier(trivyCache)
	trivyLocalScanner := local.NewScanner(trivyApplier, trivyDetector, trivyVulnClient)
	trivyScanner := scanner.NewScanner(trivyLocalScanner, trivyFSArtifact)
	trivyReport, err := trivyScanner.ScanArtifact(ctx, types.ScanOptions{
		VulnType:            []string{},
		SecurityChecks:      []string{},
		ScanRemovedPackages: false,
		ListAllPackages:     true,
	})

	createdAt := time.Now()
	duration := time.Since(scanStartedAt)
	marshaler := cyclonedx.NewMarshaler("")
	bom, err := marshaler.Marshal(trivyReport)
	if err != nil {
		return nil, err
	}

	entity := &sbommodel.SBOMEntity{
		Status: sbommodel.SBOMStatus_SUCCESS,
		Type:   sbommodel.SBOMSourceType_HOST_FILE_SYSTEM, // TODO: SBOMSourceType_LAMBDA
		Id:     "",
		InUse:  true,
		DdTags: []string{
			"function:" + scan.FunctionName,
		},
		GeneratedAt:        timestamppb.New(createdAt),
		GenerationDuration: convertDuration(duration),
		Hash:               "",
		Sbom: &sbommodel.SBOMEntity_Cyclonedx{
			Cyclonedx: convertBOM(bom),
		},
	}
	return entity, nil
}

func extractZip(zipPath, destinationPath string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		dest := filepath.Join(destinationPath, f.Name)
		if strings.HasSuffix(f.Name, "/") {
			err = os.MkdirAll(dest, 0700)
			if err != nil {
				return err
			}
		} else {
			reader, err := f.Open()
			if err != nil {
				return err
			}
			defer reader.Close()
			writer, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			defer writer.Close()
			_, err = io.Copy(writer, reader)
			if err != nil {
				return err
			}
		}
	}
	return nil
}