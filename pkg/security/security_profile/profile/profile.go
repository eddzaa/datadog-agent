// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package profile holds profile related files
package profile

import (
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"time"

	"golang.org/x/exp/slices"

	proto "github.com/DataDog/agent-payload/v5/cws/dumpsv1"
	"github.com/DataDog/datadog-go/v5/statsd"

	"github.com/DataDog/datadog-agent/pkg/security/proto/api"
	cgroupModel "github.com/DataDog/datadog-agent/pkg/security/resolvers/cgroup/model"
	timeResolver "github.com/DataDog/datadog-agent/pkg/security/resolvers/time"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	activity_tree "github.com/DataDog/datadog-agent/pkg/security/security_profile/activity_tree"
	mtdt "github.com/DataDog/datadog-agent/pkg/security/security_profile/activity_tree/metadata"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
)

// EventTypeState defines an event type state
type EventTypeState struct {
	lastAnomalyNano uint64
	state           EventFilteringProfileState
}

// VersionContext holds the context of one version (defined by its image tag)
type VersionContext struct {
	firstSeenNano uint64
	lastSeenNano  uint64

	eventTypeState map[model.EventType]*EventTypeState

	// Syscalls is the syscalls profile
	Syscalls []uint32

	// Tags defines the tags used to compute this profile, for each present profile versions
	Tags []string
}

// SecurityProfile defines a security profile
type SecurityProfile struct {
	sync.Mutex
	loadedInKernel      bool
	loadedNano          uint64
	selector            cgroupModel.WorkloadSelector
	profileCookie       uint64
	eventTypes          []model.EventType
	versionContextsLock sync.Mutex
	versionContexts     map[string]*VersionContext

	// Instances is the list of workload instances to witch the profile should apply
	Instances []*cgroupModel.CacheEntry

	// Metadata contains metadata for the current profile
	Metadata mtdt.Metadata

	// ActivityTree contains the activity tree of the Security Profile
	ActivityTree *activity_tree.ActivityTree
}

// NewSecurityProfile creates a new instance of Security Profile
func NewSecurityProfile(selector cgroupModel.WorkloadSelector, eventTypes []model.EventType) *SecurityProfile {
	// TODO: we need to keep track of which event types / fields can be used in profiles (for anomaly detection, hardening
	// or suppression). This is missing for now, and it will be necessary to smoothly handle the transition between
	// profiles that allow for evaluating new event types, and profiles that don't. As such, the event types allowed to
	// generate anomaly detections in the input of this function will need to be merged with the event types defined in
	// the configuration.
	sp := &SecurityProfile{
		selector:        selector,
		eventTypes:      eventTypes,
		versionContexts: make(map[string]*VersionContext),
	}
	if selector.Tag != "" {
		sp.versionContexts[selector.Tag] = &VersionContext{
			eventTypeState: make(map[model.EventType]*EventTypeState),
		}
	}
	return sp
}

// reset empties all internal fields so that this profile can be used again in the future
func (p *SecurityProfile) reset() {
	p.loadedInKernel = false
	p.loadedNano = 0
	p.profileCookie = 0
	p.versionContexts = make(map[string]*VersionContext)
	p.Instances = nil
}

// generateCookies computes random cookies for all the entries in the profile that require one
func (p *SecurityProfile) generateCookies() {
	p.profileCookie = utils.RandNonZeroUint64()

	// TODO: generate cookies for all the nodes in the activity tree
}

func (p *SecurityProfile) generateSyscallsFilters() [64]byte {
	var output [64]byte
	for _, pCtxt := range p.versionContexts {
		for _, syscall := range pCtxt.Syscalls {
			if syscall/8 < 64 && (1<<(syscall%8) < 256) {
				output[syscall/8] |= 1 << (syscall % 8)
			}
		}
	}
	return output
}

// MatchesSelector is used to control how an event should be added to a profile
func (p *SecurityProfile) MatchesSelector(entry *model.ProcessCacheEntry) bool {
	for _, workload := range p.Instances {
		if entry.ContainerID == workload.ID {
			return true
		}
	}
	return false
}

// IsEventTypeValid is used to control which event types should trigger anomaly detection alerts
func (p *SecurityProfile) IsEventTypeValid(evtType model.EventType) bool {
	return slices.Contains(p.eventTypes, evtType)
}

// NewProcessNodeCallback is a callback function used to propagate the fact that a new process node was added to the activity tree
func (p *SecurityProfile) NewProcessNodeCallback(_ *activity_tree.ProcessNode) {
	// TODO: debounce and regenerate profile filters & programs
}

// LoadProfileFromFile loads profile from file
func LoadProfileFromFile(filepath string) (*proto.SecurityProfile, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("couldn't open profile: %w", err)
	}
	defer f.Close()

	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("couldn't open profile: %w", err)
	}

	profile := &proto.SecurityProfile{}
	if err = profile.UnmarshalVT(raw); err != nil {
		return nil, fmt.Errorf("couldn't decode protobuf profile: %w", err)
	}
	return profile, nil
}

// SendStats sends profile stats
func (p *SecurityProfile) SendStats(client statsd.ClientInterface) error {
	p.Lock()
	defer p.Unlock()
	return p.ActivityTree.SendStats(client)
}

// ToSecurityProfileMessage returns a SecurityProfileMessage filled with the content of the current Security Profile
func (p *SecurityProfile) ToSecurityProfileMessage(timeResolver *timeResolver.Resolver) *api.SecurityProfileMessage {
	// construct the list of image tags for this profile
	imageTags := ""
	for key := range p.versionContexts {
		if imageTags != "" {
			imageTags = imageTags + ","
		}
		imageTags = imageTags + key
	}

	msg := &api.SecurityProfileMessage{
		LoadedInKernel:          p.loadedInKernel,
		LoadedInKernelTimestamp: timeResolver.ResolveMonotonicTimestamp(p.loadedNano).String(),
		Selector: &api.WorkloadSelectorMessage{
			Name: p.selector.Image,
			Tag:  imageTags,
		},
		ProfileCookie: p.profileCookie,
		Metadata: &api.MetadataMessage{
			Name: p.Metadata.Name,
		},
		ProfileGlobalState: p.GetGlobalState().toTag(),
	}
	if p.ActivityTree != nil {
		msg.Stats = &api.ActivityTreeStatsMessage{
			ProcessNodesCount: p.ActivityTree.Stats.ProcessNodes,
			FileNodesCount:    p.ActivityTree.Stats.FileNodes,
			DNSNodesCount:     p.ActivityTree.Stats.DNSNodes,
			SocketNodesCount:  p.ActivityTree.Stats.SocketNodes,
			ApproximateSize:   p.ActivityTree.Stats.ApproximateSize(),
		}
	}

	for _, evt := range p.eventTypes {
		msg.EventTypes = append(msg.EventTypes, evt.String())
	}

	for _, inst := range p.Instances {
		msg.Instances = append(msg.Instances, &api.InstanceMessage{
			ContainerID: inst.ID,
			Tags:        inst.Tags,
		})
	}
	return msg
}

// GetState returns the state of a profile for a given imageTag
func (p *SecurityProfile) GetState(imageTag string) EventFilteringProfileState {
	p.versionContextsLock.Lock()
	defer p.versionContextsLock.Unlock()
	pCtx, ok := p.versionContexts[imageTag]
	if !ok {
		return NoProfile
	}
	state := StableEventType
	for _, et := range p.eventTypes {
		if pCtx.eventTypeState[et].state == UnstableEventType {
			return UnstableEventType
		} else if pCtx.eventTypeState[et].state != StableEventType {
			state = AutoLearning
		}
	}
	return state
}

// GetGlobalState returns the global state of a profile: AutoLearning, StableEventType or UnstableEventType
func (p *SecurityProfile) GetGlobalState() EventFilteringProfileState {
	globalState := AutoLearning
	for imageTag := range p.versionContexts {
		state := p.GetState(imageTag)
		if state == UnstableEventType {
			return UnstableEventType
		} else if state == StableEventType {
			globalState = StableEventType
		}
	}
	return globalState // AutoLearning or StableEventType
}

// GetGlobalEventTypeState returns the global state of a profile for a given event type: AutoLearning, StableEventType or UnstableEventType
func (p *SecurityProfile) GetGlobalEventTypeState(et model.EventType) EventFilteringProfileState {
	globalState := AutoLearning
	for _, ctx := range p.versionContexts {
		state := ctx.eventTypeState[et].state
		if state == UnstableEventType {
			return UnstableEventType
		} else if state == StableEventType {
			globalState = StableEventType
		}
	}
	return globalState // AutoLearning or StableEventType
}

func (p *SecurityProfile) evictProfileVersion() {
	if len(p.versionContexts) <= 0 {
		return // should not happen
	}

	oldest := uint64(math.MaxUint64)
	oldestImageTag := ""

	// select the oldest image tag
	// TODO: not 100% sure to select the first or the lastSeenNano
	for imageTag, profileCtx := range p.versionContexts {
		if profileCtx.lastSeenNano < oldest {
			oldest = profileCtx.lastSeenNano
			oldestImageTag = imageTag
		}
	}
	// delete image context
	delete(p.versionContexts, oldestImageTag)

	// then, remove every trace of this version from the tree
	p.ActivityTree.EvictImageTag(oldestImageTag)
}

func (p *SecurityProfile) makeRoomForNewVersion(maxImageTags int) {
	// if we reached the max number of versions, we should evict the surplus
	surplus := len(p.versionContexts) - maxImageTags + 1
	for surplus > 0 {
		p.evictProfileVersion()
		surplus--
	}
}

func (p *SecurityProfile) prepareNewVersion(newImageTag string, tags []string, maxImageTags int) {
	// prepare new profile context to be inserted
	newProfileCtx := &VersionContext{
		eventTypeState: make(map[model.EventType]*EventTypeState),
		firstSeenNano:  uint64(time.Now().UnixNano()),
		lastSeenNano:   uint64(time.Now().UnixNano()),
		Tags:           tags,
	}

	// add the new profile context to the list
	// (versionContextsLock already locked here)
	p.makeRoomForNewVersion(maxImageTags)
	p.versionContexts[newImageTag] = newProfileCtx
}

func (p *SecurityProfile) mergeNewVersion(newVersion *SecurityProfile, maxImageTags int) {
	newImageTag := newVersion.selector.Tag
	_, ok := p.versionContexts[newImageTag]
	if ok { // should not happen: if new tag already exists, ignore
		return
	}
	// prepare new profile context to be inserted
	newVersion.versionContexts[newImageTag].firstSeenNano = uint64(time.Now().UnixNano())
	newVersion.versionContexts[newImageTag].lastSeenNano = uint64(time.Now().UnixNano())
	newProfileCtx, ok := newVersion.versionContexts[newImageTag]
	if !ok { // should not happen neither
		return
	}

	// add the new profile context to the list
	p.versionContextsLock.Lock()
	defer p.versionContextsLock.Unlock()
	p.makeRoomForNewVersion(maxImageTags)
	p.versionContexts[newImageTag] = newProfileCtx

	// finally, merge the trees
	p.ActivityTree.Merge(newVersion.ActivityTree)
}
