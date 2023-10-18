// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package activitytree holds activitytree related files
package activitytree

import (
	"strings"

	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	"golang.org/x/exp/slices"
)

// DNSNode is used to store a DNS node
type DNSNode struct {
	MatchedRules []*model.MatchedRule
	ImageTags    []string

	GenerationType NodeGenerationType
	Requests       []model.DNSEvent
}

func (dn *DNSNode) merge(new *DNSNode) {
	// merge image tags
	if len(new.ImageTags) > 0 {
		dn.ImageTags = append(dn.ImageTags, new.ImageTags...)
		dn.ImageTags = slices.Compact(dn.ImageTags)
	}

	// merge requests
	// loop on new requests
	reqsToAdd := []model.DNSEvent{}
	for _, newReq := range new.Requests {
		// search them on current dns node
		if !slices.ContainsFunc(dn.Requests, func(current model.DNSEvent) bool {
			return current.Matches(&newReq)
		}) {
			// if not found, add it
			reqsToAdd = append(reqsToAdd, newReq)
		}
	}
	if len(reqsToAdd) > 0 {
		dn.Requests = append(dn.Requests, reqsToAdd...)
	}
}

// NewDNSNode returns a new DNSNode instance
func NewDNSNode(event *model.DNSEvent, rules []*model.MatchedRule, generationType NodeGenerationType, imageTag string) *DNSNode {
	node := &DNSNode{
		MatchedRules:   rules,
		GenerationType: generationType,
		Requests:       []model.DNSEvent{*event},
	}
	if imageTag != "" {
		node.ImageTags = []string{imageTag}
	}
	return node
}

func dnsFilterSubdomains(name string, maxDepth int) string {
	tab := strings.Split(name, ".")
	if len(tab) < maxDepth {
		return name
	}
	result := ""
	for i := 0; i < maxDepth; i++ {
		if result != "" {
			result = "." + result
		}
		result = tab[len(tab)-i-1] + result
	}
	return result
}

func (dn *DNSNode) appendImageTag(imageTag string) {
	if imageTag != "" && !slices.Contains(dn.ImageTags, imageTag) {
		dn.ImageTags = append(dn.ImageTags, imageTag)
	}
}

func (dn *DNSNode) evictImageTag(imageTag string, DNSNames *utils.StringKeys) bool {
	if imageTag != "" && slices.Contains(dn.ImageTags, imageTag) {
		dn.ImageTags = removeImageTagFromList(dn.ImageTags, imageTag)
		if len(dn.ImageTags) == 0 {
			return true
		}
	}
	// also, reconstruct the list of all DNS requests
	if len(dn.Requests) > 0 {
		DNSNames.Insert(dn.Requests[0].Name)
	}
	return false
}
