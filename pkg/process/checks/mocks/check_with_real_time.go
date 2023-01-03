// Code generated by mockery v2.16.0. DO NOT EDIT.

package mocks

import (
	checks "github.com/DataDog/datadog-agent/pkg/process/checks"
	mock "github.com/stretchr/testify/mock"

	process "github.com/DataDog/agent-payload/v5/process"
)

// CheckWithRealTime is an autogenerated mock type for the CheckWithRealTime type
type CheckWithRealTime struct {
	mock.Mock
}

// Cleanup provides a mock function with given fields:
func (_m *CheckWithRealTime) Cleanup() {
	_m.Called()
}

// Init provides a mock function with given fields: syscfg, info
func (_m *CheckWithRealTime) Init(syscfg *checks.SysProbeConfig, info *checks.HostInfo) error {
	ret := _m.Called(syscfg, info)

	var r0 error
	if rf, ok := ret.Get(0).(func(*checks.SysProbeConfig, *checks.HostInfo) error); ok {
		r0 = rf(syscfg, info)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Name provides a mock function with given fields:
func (_m *CheckWithRealTime) Name() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// RealTime provides a mock function with given fields:
func (_m *CheckWithRealTime) RealTime() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// RealTimeName provides a mock function with given fields:
func (_m *CheckWithRealTime) RealTimeName() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Run provides a mock function with given fields: groupID
func (_m *CheckWithRealTime) Run(groupID int32) ([]process.MessageBody, error) {
	ret := _m.Called(groupID)

	var r0 []process.MessageBody
	if rf, ok := ret.Get(0).(func(int32) []process.MessageBody); ok {
		r0 = rf(groupID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]process.MessageBody)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int32) error); ok {
		r1 = rf(groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RunWithOptions provides a mock function with given fields: nextGroupID, options
func (_m *CheckWithRealTime) RunWithOptions(nextGroupID func() int32, options checks.RunOptions) (*checks.RunResult, error) {
	ret := _m.Called(nextGroupID, options)

	var r0 *checks.RunResult
	if rf, ok := ret.Get(0).(func(func() int32, checks.RunOptions) *checks.RunResult); ok {
		r0 = rf(nextGroupID, options)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*checks.RunResult)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(func() int32, checks.RunOptions) error); ok {
		r1 = rf(nextGroupID, options)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ShouldSaveLastRun provides a mock function with given fields:
func (_m *CheckWithRealTime) ShouldSaveLastRun() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

type mockConstructorTestingTNewCheckWithRealTime interface {
	mock.TestingT
	Cleanup(func())
}

// NewCheckWithRealTime creates a new instance of CheckWithRealTime. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewCheckWithRealTime(t mockConstructorTestingTNewCheckWithRealTime) *CheckWithRealTime {
	mock := &CheckWithRealTime{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
