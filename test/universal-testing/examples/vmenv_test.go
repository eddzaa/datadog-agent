// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package examples

import (
	"flag"
	"os"
	"path"
	"testing"

	tests "github.com/DataDog/datadog-agent/test/universal-testing"
	"github.com/DataDog/datadog-agent/test/universal-testing/infra/localvmparams"
	"github.com/DataDog/test-infra-definitions/scenarios/aws/vm/ec2os"
	"github.com/DataDog/test-infra-definitions/scenarios/aws/vm/ec2params"
	"github.com/stretchr/testify/assert"
)

var runLocally = flag.Bool("runLocally", false, "run tests on a local VM")

type vmSuiteExample struct {
	tests.Suite[tests.VMEnv]
}

func TestVMSuiteEx(t *testing.T) {
	var testEnvironment tests.InfraProvider[tests.VMEnv]
	if *runLocally {
		homeDir, _ := os.UserHomeDir()
		testEnvironment = tests.LocalVMDef(localvmparams.WithJSONFile(path.Join(homeDir, ".test_config.json")))
	} else {
		testEnvironment = tests.EC2VMStackDef(ec2params.WithOS(ec2os.WindowsOS))
	}

	tests.Run(t, &vmSuiteExample{}, testEnvironment)
}

func (v *vmSuiteExample) TestItIsWindows() {
	res := v.Env().VM.Execute("dir C:\\")
	assert.Contains(v.T(), res, "Windows")
}
