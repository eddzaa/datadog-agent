// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package javaparser contains functions to autodetect service name for java applications
package javaparser

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickar/props"
	"github.com/vibrantbyte/go-antpath/antpath"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	defaultLocations       = "optional:classpath:/;optional:classpath:/config/;optional:file:./;optional:file:./config/;optional:file:./config/*/"
	defaultConfigName      = "application"
	locationPropName       = "spring.config.locations"
	configPropName         = "spring.config.name"
	activeProfilesPropName = "spring.profiles.active"

	appnamePropName = "spring.application.name"
)

// parseURI parses locations (usually specified by the property locationPropName) given the list of active profiles (specified by activeProfilesPropName)
// and the current directory cwd.
// It returns a couple of maps each having as key the profile name ("" stands for default one) and as value the ant patterns where the properties should be found
// The first map returned is the locations to be found in fs while the second map contains locations on the classpath (usually inside the application jar)
func parseURI(locations []string, name string, profiles []string, cwd string) (map[string][]string, map[string][]string) {
	classpaths := make(map[string][]string)
	files := make(map[string][]string)
	for _, current := range locations {
		parts := strings.Split(current, ":")
		pl := len(parts)

		isClasspath := false
		if pl > 1 && parts[pl-2] == "classpath" {
			parts[pl-1] = "BOOT-INF/classes/" + parts[pl-1]
			isClasspath = true
		}

		doAppend := func(name string, profile string) {
			name = filepath.Clean(name)
			if isClasspath {
				classpaths[profile] = append(classpaths[profile], filepath.ToSlash(name))
			} else {
				files[profile] = append(files[profile], filepath.ToSlash(abs(name, cwd)))
			}
		}
		if strings.HasSuffix(parts[pl-1], "/") {
			// we have a path: add all the possible filenames
			tmp := parts[pl-1] + name
			// there is an extension based priority also: first properties then yaml
			for _, profile := range profiles {
				tmp2 := tmp + "-" + profile
				for _, ext := range []string{".properties", ".yaml", ".yml"} {
					doAppend(tmp2+ext, profile)
				}
			}
			for _, ext := range []string{".properties", ".yaml", ".yml"} {
				doAppend(tmp+ext, "")
			}
		} else {
			// just add it since it's a direct file
			doAppend(parts[pl-1], "")
		}
	}
	return files, classpaths
}

// abs returns the absolute path resolved from cws if not already absolute
// it slightly differs from the golang built in version because on windows the built-in considers absolute a path only
// if the volume name is specified. This one only requires a path to begin with os.PathSeparator to be absolute
func abs(path string, cwd string) string {
	// on windows IsAbs likely returns false when the drive is missing
	// hence, since we accept also paths, we test if the first char is a path separator
	if !(filepath.IsAbs(path) || path[0] == os.PathSeparator) && len(cwd) > 0 {
		return filepath.Join(cwd, path)
	}
	return path
}

// newSpringBootArchiveSourceFromReader return a PropertyGetter combined source with properties sources from the jar application.
func newSpringBootArchiveSourceFromReader(reader *zip.Reader, patternMap map[string][]string) map[string]*props.Combined {
	ret := make(map[string]*props.Combined)
	// probably we need something more efficient
	matcher := antpath.New()
	for _, f := range reader.File {
		name := f.Name
		// the generalized approach implies visiting also jar in BOOT-INF/lib but here we skip it
		// to minimize the scanning time given that the general habit is to package config
		// directly into the application and not in a lib embedded into the app
		if strings.HasPrefix(name, "BOOT-INF/classes/") {
			for profile, patterns := range patternMap {
				for _, pattern := range patterns {
					if matcher.Match(pattern, name) {
						rc, err := f.Open()
						if err != nil {
							log.Trace("Unable to open", name, ":", err)
						} else {
							source, err := func() (*props.PropertyGetter, error) {
								defer rc.Close()
								source, err := newPropertySourceFromStream(rc, f.Name, f.UncompressedSize64)
								return source, err
							}()
							if err != nil {
								log.Trace("Error creating property source", err)
							} else {
								log.Trace("Loaded", f.Name)
								val, ok := ret[profile]
								if !ok {
									val = &props.Combined{Sources: []props.PropertyGetter{}}
									ret[profile] = val
								}
								val.Sources = append(val.Sources, *source)
							}
						}
						break
					}
				}
			}
		}
	}
	return ret
}

// GetSpringBootAppName tries to autodetect the name of a spring boot application given its working dir,
// the jar path and the application arguments
func GetSpringBootAppName(cwd string, jarname string, args []string) (string, error) {
	absName := abs(jarname, cwd)
	log.Tracef("open jar archive %s", absName)
	archive, err := zip.OpenReader(jarname)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	ok, err := IsSpringBootArchive(&archive.Reader)
	if !ok || err != nil {
		log.Trace("Not a spring boot archive.")
		return "", nil
	}

	combined := &props.Combined{Sources: []props.PropertyGetter{
		newArgumentSource(args, "--"),
		newArgumentSource(args, "-D"),
		// TODO: add the env variable of the process being introspected
		// I did not found in the agent packages something to do it cross os.
		// On linux one trivial way is to look in the proc fs
		//&props.Environment{Normalize: true},
	}}

	// resolved properties referring to other properties just in case...
	conf := &props.Configuration{Props: props.NewExpander(combined)}
	// Looking in the environment (sysprops, arguments) first
	appname, ok := conf.Get(appnamePropName)
	if !ok {
		locations := strings.Split(combined.GetDefault(locationPropName, defaultLocations), ";")
		confname := combined.GetDefault(configPropName, defaultConfigName)
		var profiles []string
		rawProfile, ok := combined.Get(activeProfilesPropName)
		if ok && len(rawProfile) > 0 {
			profiles = strings.Split(rawProfile, ",")
		}
		log.Trace("Parsing spring configuration from locations", locations, "with configuration name", confname)
		files, classpaths := parseURI(locations, confname, profiles, cwd)
		log.Trace("Loading filesystem properties from", files)
		fileSources := scanSourcesFromFileSystem(files)
		log.Trace("Loading archive properties from classpath", classpaths)
		classpathSources := newSpringBootArchiveSourceFromReader(&archive.Reader, classpaths)
		//assemble by profile
		for _, profile := range append(profiles, "") {
			val, ok := fileSources[profile]
			if ok {
				combined.Sources = append(combined.Sources, val)
			}
			val, ok = classpathSources[profile]
			if ok {
				combined.Sources = append(combined.Sources, val)
			}
		}

		if err != nil {
			return "", err
		}

		appname, _ = conf.Get(appnamePropName)
	}
	return appname, nil
}

// IsSpringBootArchive heuristically determines if a jar archive is a spring boot packaged jar
func IsSpringBootArchive(reader *zip.Reader) bool {
	for _, f := range reader.File {
		if f.Name == "BOOT-INF/" {
			return true
		}
	}
	return false
}
