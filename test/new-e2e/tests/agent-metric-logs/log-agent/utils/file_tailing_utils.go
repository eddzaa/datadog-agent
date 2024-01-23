// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package utils provides shared common functions so different E2E tests suites can use them.
package utils

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/test/fakeintake/aggregator"
	fi "github.com/DataDog/datadog-agent/test/fakeintake/client"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"

	"github.com/DataDog/test-infra-definitions/components/os"
)

// LinuxLogsFolderPath is the folder where log files will be stored for Linux tests
const LinuxLogsFolderPath = "/var/log/e2e_test_logs"

// WindowsLogsFolderPath is the folder where log files will be stored for Windows tests
const WindowsLogsFolderPath = "C:\\logs\\e2e_test_logs"

// LogsTestSuite is an interface for the log agent test suite.
type LogsTestSuite interface {
	T() *testing.T
	Env() *environments.Host
	IsDevMode() bool
}

// AppendLog append log with 'content', which is then repeated 'reccurrence' times and verifies log contents.
func AppendLog(ls LogsTestSuite, logFile, content string, recurrence int) {
	// Determine the OS and set the appropriate log path and command.
	var cmd, checkCmd string
	t := ls.T()
	t.Helper()

	var osStr string
	switch ls.Env().RemoteHost.OSFamily {
	case os.WindowsFamily:
		osStr = "windows"
		t.Log("Generating Windows log.")
		cmd = fmt.Sprintf("echo %s > %s\\%s", strings.Repeat(content+" ", recurrence), WindowsLogsFolderPath, logFile)
		checkCmd = fmt.Sprintf("Get-Content %s\\%s", WindowsLogsFolderPath, logFile)
	default: // Assuming Linux if not Windows.
		osStr = "linux"
		t.Log("Generating Linux log.")
		cmd = fmt.Sprintf("echo '%s' | sudo tee -a %s/%s", strings.Repeat(content+" ", recurrence), LinuxLogsFolderPath, logFile)
		checkCmd = fmt.Sprintf("sudo cat %s/%s", LinuxLogsFolderPath, logFile)
	}

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		// Generate the log content
		output, err := ls.Env().RemoteHost.Execute(cmd)
		if err != nil {
			assert.FailNowf(c, "Having issue generating %s log with error: %s", osStr, output)
		}
		// Verify the log content locally
		output, err = ls.Env().RemoteHost.Execute(checkCmd)
		if err != nil {
			assert.FailNowf(c, "Log content %s not found, instead received:: %s", content, output)
		}
		if strings.Contains(output, content) {
			t.Logf("Finished generating %s log with content: '%s' \n", osStr, content)
		}
	}, 2*time.Minute, 10*time.Second)
}

// CheckLogFilePresence verifies the presence or absence of a log file path
func CheckLogFilePresence(ls LogsTestSuite, logFile string) {
	t := ls.T()
	t.Helper()

	switch ls.Env().RemoteHost.OSFamily {
	case os.WindowsFamily:
		checkCmd := fmt.Sprintf("Get-Content %s\\%s", WindowsLogsFolderPath, logFile)
		_, err := ls.Env().RemoteHost.Execute(checkCmd)
		if err != nil {
			assert.FailNow(t, "Log File not found")
		}
	default: // Assuming Linux if not Windows.
		checkCmd := fmt.Sprintf("sudo cat %s/%s", LinuxLogsFolderPath, logFile)
		_, err := ls.Env().RemoteHost.Execute(checkCmd)
		if err != nil {
			assert.FailNow(t, "Log File not found")
		}
	}
}

// CheckLogs verifies the presence or absence of logs in the intake based on the expectLogs flag.
func CheckLogs(ls LogsTestSuite, service, content string, expectLogs bool) {
	client := ls.Env().FakeIntake.Client()
	t := ls.T()
	t.Helper()
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		names, err := client.GetLogServiceNames()
		if !assert.NoErrorf(c, err, "Error found: %s", err) {
			return
		}
		if len(names) > 0 {
			logs, err := client.FilterLogs(service)
			if !assert.NoErrorf(c, err, "Error found: %s", err) {
				return
			}
			if !assert.NotEmpty(c, logs, "No logs with service matching '%s' found, instead got '%s'", service, names) {
				return
			}
			logs, err = client.FilterLogs(service, fi.WithMessageMatching(content))
			intakeLogs := logsToString(logs)
			assert.NoErrorf(c, err, "Error found: %s", err)
			if expectLogs {
				t.Logf("Logs from service: '%s' with content: '%s' collected", names, content)
				assert.NotEmpty(c, logs, "Expected at least 1 log with content: '%s', from service: %s but received %s logs.", content, names, intakeLogs)
			} else {
				t.Logf("No logs from service: '%s' with content: '%s' collected as expected", names, content)
				assert.Empty(c, logs, "No logs with content: '%s' is expected to be found from service: %s instead found: %s", content, names, intakeLogs)
			}
		}
	}, 2*time.Minute, 10*time.Second)
}

// CleanUp cleans up any existing log files (only useful when running dev mode/local runs).
func CleanUp(ls LogsTestSuite) {
	t := ls.T()
	t.Helper()
	var checkCmd string

	if ls.IsDevMode() {
		switch ls.Env().RemoteHost.OSFamily {
		default: // default is linux
			ls.Env().RemoteHost.MustExecute(fmt.Sprintf("sudo rm -rf %s", LinuxLogsFolderPath))
			checkCmd = fmt.Sprintf("ls %s 2>/dev/null || echo 'Files do not exist'", LinuxLogsFolderPath)
		case os.WindowsFamily:
			ls.Env().RemoteHost.MustExecute(fmt.Sprintf("if (Test-Path %s) { Remove-Item -Path %s -Force }", WindowsLogsFolderPath, WindowsLogsFolderPath))
			checkCmd = fmt.Sprintf("if (Test-Path %s) { Get-ChildItem -Path %s } else { Write-Output 'Files do not exist' }", WindowsLogsFolderPath, WindowsLogsFolderPath)
		}

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			output, err := ls.Env().RemoteHost.Execute(checkCmd)
			if assert.NoErrorf(c, err, "Having issue cleaning up log files, retrying... %s", output) {
				t.Log("Successfully cleaned up log files.")
			}
		}, 1*time.Minute, 10*time.Second)
	}

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := ls.Env().FakeIntake.Client().FlushServerAndResetAggregators()
		if assert.NoErrorf(c, err, "Having issue flushing server and resetting aggregators, retrying...") {
			t.Log("Successfully flushed server and reset aggregators.")
		}
	}, 1*time.Minute, 10*time.Second)
}

// prettyPrintLog pretty prints a log entry.
func prettyPrintLog(log *aggregator.Log) string {
	// Unmarshal and re-marshal the message field for pretty printing
	var messageObj map[string]interface{}
	if err := json.Unmarshal([]byte(log.Message), &messageObj); err == nil {
		prettyMessage, _ := json.MarshalIndent(messageObj, "", "  ")
		log.Message = string(prettyMessage)
	}
	// Marshal the entire log entry
	logStr, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		// Handle the error appropriately
		return fmt.Sprintf("Error marshaling log: %v", err)
	}
	return string(logStr)
}

// logsToString converts a slice of logs to a string.
func logsToString(logs []*aggregator.Log) string {
	var logsStrings []string
	for _, log := range logs {
		logsStrings = append(logsStrings, prettyPrintLog(log))
	}
	return fmt.Sprintf("[%s]", strings.Join(logsStrings, ",\n"))
}
