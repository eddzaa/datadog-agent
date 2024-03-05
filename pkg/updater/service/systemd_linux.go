// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package service provides a way to interact with os services
package service

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/fifo"
)

type unitCommand string

const (
	startUnit     = unitCommand("start")
	stopUnit      = unitCommand("stop")
	enableUnit    = unitCommand("enable")
	disableUnit   = unitCommand("disable")
	loadUnit      = unitCommand("load-unit")
	removeUnit    = unitCommand("remove-systemd")
	systemdReload = "systemd-reload"
	path          = "/opt/datadog/updater/run/"
	adminExecutor = "datadog-updater-admin.service"
	inFifo        = path + "in.fifo"
	outFifo       = path + "out.fifo"
)

type scriptRunner struct {
	inFifo  io.ReadWriteCloser
	outFifo io.ReadWriteCloser
}

func newScriptRunner() (*scriptRunner, error) {
	_ = os.Remove(inFifo)
	_ = os.Remove(outFifo)
	// start with outFifo creation first as inFifo can trigger the path
	outFifo, err := fifo.OpenFifo(context.Background(), outFifo, syscall.O_CREAT|syscall.O_RDONLY|syscall.O_NONBLOCK, 0660)
	if err != nil {
		return nil, fmt.Errorf("error opening out.fifo: %s", err)
	}
	inFifo, err := fifo.OpenFifo(context.Background(), inFifo, syscall.O_CREAT|syscall.O_WRONLY|syscall.O_NONBLOCK, 0660)
	if err != nil {
		outFifo.Close()
		return nil, fmt.Errorf("error opening in.fifo: %s", err)
	}
	return &scriptRunner{
		inFifo:  inFifo,
		outFifo: outFifo,
	}, nil
}

func (s *scriptRunner) stopUnit(unit string) error {
	return s.executeCommand(wrapUnitCommand(stopUnit, unit))
}

func (s *scriptRunner) startUnit(unit string) error {
	return s.executeCommand(wrapUnitCommand(startUnit, unit))
}

func (s *scriptRunner) enableUnit(unit string) error {
	return s.executeCommand(wrapUnitCommand(enableUnit, unit))
}

func (s *scriptRunner) disableUnit(unit string) error {
	return s.executeCommand(wrapUnitCommand(disableUnit, unit))
}

func (s *scriptRunner) loadUnit(unit string) error {
	return s.executeCommand(wrapUnitCommand(loadUnit, unit))
}

func (s *scriptRunner) removeUnit(unit string) error {
	return s.executeCommand(wrapUnitCommand(removeUnit, unit))
}

func (s *scriptRunner) systemdReload() error {
	return s.executeCommand(string(systemdReload))
}

func (s *scriptRunner) executeCommand(command string) error {
	err := wrapWithTimeout(func() error {
		_, err := s.inFifo.Write([]byte(command))
		return err
	})
	if err != nil {
		return fmt.Errorf("error executing command %s while writing to fifo: %s", command, err)
	}
	res := make([]byte, 1<<6)
	err = wrapWithTimeout(func() error {
		n, err := s.outFifo.Read(res)
		res = res[:n]
		return err
	})
	if err != nil {
		return fmt.Errorf("error executing command %s while reading from fifo: %s", command, err)
	}
	result := strings.TrimRight(string(res), "\n")
	if result != "success" {
		return fmt.Errorf("error executing command %s: %s", command, result)
	}
	return nil
}

func (s *scriptRunner) Close() {
	s.inFifo.Close()
	_ = os.Remove(inFifo)
	s.outFifo.Close()
}

func wrapUnitCommand(command unitCommand, unit string) string {
	return string(command) + " " + unit
}

func wrapWithTimeout(fn func() error) error {
	err := make(chan error, 1)
	go func() {
		err <- fn()
	}()
	select {
	case <-time.After(3 * time.Second):
		return fmt.Errorf("timeout")
	case e := <-err:
		return e
	}
}
