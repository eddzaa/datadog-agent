// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package module

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"unsafe"

	"github.com/hashicorp/go-multierror"
	"go.uber.org/atomic"

	sapi "github.com/DataDog/datadog-agent/pkg/security/api"
	"github.com/DataDog/datadog-agent/pkg/security/config"
	"github.com/DataDog/datadog-agent/pkg/security/events"
	"github.com/DataDog/datadog-agent/pkg/security/probe"
	sprobe "github.com/DataDog/datadog-agent/pkg/security/probe"
	"github.com/DataDog/datadog-agent/pkg/security/probe/selftests"
	"github.com/DataDog/datadog-agent/pkg/security/rconfig"
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
	"github.com/DataDog/datadog-go/v5/statsd"
)

// CWS represents the system-probe module for the runtime security agent
type CWS struct {
	sync.RWMutex
	config       *config.Config
	probe        *probe.Probe
	statsdClient statsd.ClientInterface

	// internals
	wg               sync.WaitGroup
	ctx              context.Context
	cancelFnc        context.CancelFunc
	currentRuleSet   *atomic.Value
	reloading        *atomic.Bool
	apiServer        *APIServer
	rateLimiter      *RateLimiter
	sigupChan        chan os.Signal
	rulesLoaded      func(rs *rules.RuleSet, err *multierror.Error)
	policiesVersions []string
	policyProviders  []rules.PolicyProvider
	policyLoader     *rules.PolicyLoader
	policyOpts       rules.PolicyLoaderOpts
	selfTester       *selftests.SelfTester
	policyMonitor    *PolicyMonitor
	sendStatsChan    chan chan bool
	eventSender      EventSender
}

// Init initializes the module
func NewCWS(module *Module) (EventModule, error) {
	selfTester, err := selftests.NewSelfTester()
	if err != nil {
		seclog.Errorf("unable to instantiate self tests: %s", err)
	}

	ctx, cancelFnc := context.WithCancel(context.Background())

	c := &CWS{
		config:       module.Config,
		probe:        module.Probe,
		statsdClient: module.StatsdClient,
		// internals
		ctx:            ctx,
		cancelFnc:      cancelFnc,
		currentRuleSet: new(atomic.Value),
		reloading:      atomic.NewBool(false),
		apiServer:      NewAPIServer(module.Config, module.Probe, module.StatsdClient),
		rateLimiter:    NewRateLimiter(module.StatsdClient),
		sigupChan:      make(chan os.Signal, 1),
		selfTester:     selfTester,
		policyMonitor:  NewPolicyMonitor(module.StatsdClient),
		sendStatsChan:  make(chan chan bool, 1),
	}
	c.apiServer.cws = c

	/*if len(opts) > 0 && opts[0].EventSender != nil {
		c.eventSender = opts[0].EventSender
	} else {
		c.eventSender = c
	}*/

	seclog.SetPatterns(module.Config.LogPatterns...)
	seclog.SetTags(module.Config.LogTags...)

	sapi.RegisterSecurityModuleServer(module.GRPCServer, c.apiServer)

	module.Probe.AddEventHandler(model.UnknownEventType, c)
	module.Probe.AddActivityDumpHandler(c)

	// policy loader
	c.policyLoader = rules.NewPolicyLoader()

	return c, nil
}

func (c *CWS) EventHanlders() map[model.EventType]sprobe.EventHandler {
	return map[model.EventType]sprobe.EventHandler{
		model.UnknownEventType: c,
	}
}

// Start the module
func (c *CWS) Start() error {
	// start api server
	sapi.RegisterVTCodec()
	c.apiServer.Start(c.ctx)

	// monitor policies
	if c.config.PolicyMonitorEnabled {
		c.policyMonitor.Start(c.ctx)
	}

	if c.config.SelfTestEnabled && c.selfTester != nil {
		_ = c.RunSelfTest(true)
	}

	var policyProviders []rules.PolicyProvider

	agentVersion, err := utils.GetAgentSemverVersion()
	if err != nil {
		seclog.Errorf("failed to parse agent version: %v", err)
	}

	var macroFilters []rules.MacroFilter
	var ruleFilters []rules.RuleFilter

	agentVersionFilter, err := rules.NewAgentVersionFilter(agentVersion)
	if err != nil {
		seclog.Errorf("failed to create agent version filter: %v", err)
	} else {
		macroFilters = append(macroFilters, agentVersionFilter)
		ruleFilters = append(ruleFilters, agentVersionFilter)
	}

	kv, err := c.probe.GetKernelVersion()
	if err != nil {
		seclog.Errorf("failed to create rule filter model: %v", err)
	}
	ruleFilterModel := NewRuleFilterModel(kv)
	seclRuleFilter := rules.NewSECLRuleFilter(ruleFilterModel)
	macroFilters = append(macroFilters, seclRuleFilter)
	ruleFilters = append(ruleFilters, seclRuleFilter)

	c.policyOpts = rules.PolicyLoaderOpts{
		MacroFilters: macroFilters,
		RuleFilters:  ruleFilters,
	}

	// directory policy provider
	if provider, err := rules.NewPoliciesDirProvider(c.config.PoliciesDir, c.config.WatchPoliciesDir); err != nil {
		seclog.Errorf("failed to load policies: %s", err)
	} else {
		policyProviders = append(policyProviders, provider)
	}

	// add remote config as config provider if enabled
	if c.config.RemoteConfigurationEnabled {
		rcPolicyProvider, err := rconfig.NewRCPolicyProvider("security-agent", agentVersion)
		if err != nil {
			seclog.Errorf("will be unable to load remote policy: %s", err)
		} else {
			policyProviders = append(policyProviders, rcPolicyProvider)
		}
	}

	if err := c.LoadPolicies(policyProviders, true); err != nil {
		seclog.Errorf("failed to load policies: %s", err)
	}

	c.wg.Add(1)
	go c.statsSender()

	signal.Notify(c.sigupChan, syscall.SIGHUP)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()

		for range c.sigupChan {
			if err := c.ReloadPolicies(); err != nil {
				seclog.Errorf("failed to reload policies: %s", err)
			}
		}
	}()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()

		for range c.policyLoader.NewPolicyReady() {
			if err := c.ReloadPolicies(); err != nil {
				seclog.Errorf("failed to reload policies: %s", err)
			}
		}
	}()

	for _, provider := range c.policyProviders {
		provider.Start()
	}

	return nil
}

func (c *CWS) displayReport(report *sprobe.Report) {
	content, _ := json.Marshal(report)
	seclog.Debugf("Policy report: %s", content)
}

func (c *CWS) getEventTypeEnabled() map[eval.EventType]bool {
	enabled := make(map[eval.EventType]bool)

	categories := model.GetEventTypePerCategory()

	if c.config.FIMEnabled {
		if eventTypes, exists := categories[model.FIMCategory]; exists {
			for _, eventType := range eventTypes {
				enabled[eventType] = true
			}
		}
	}

	if c.config.NetworkEnabled {
		if eventTypes, exists := categories[model.NetworkCategory]; exists {
			for _, eventType := range eventTypes {
				enabled[eventType] = true
			}
		}
	}

	if c.config.RuntimeEnabled {
		// everything but FIM
		for _, category := range model.GetAllCategories() {
			if category == model.FIMCategory || category == model.NetworkCategory {
				continue
			}

			if eventTypes, exists := categories[category]; exists {
				for _, eventType := range eventTypes {
					enabled[eventType] = true
				}
			}
		}
	}

	return enabled
}

func getPoliciesVersions(rs *rules.RuleSet) []string {
	var versions []string

	cache := make(map[string]bool)
	for _, rule := range rs.GetRules() {
		version := rule.Definition.Policy.Version

		if _, exists := cache[version]; !exists {
			cache[version] = true

			versions = append(versions, version)
		}
	}

	return versions
}

// ReloadPolicies reloads the policies
func (c *CWS) ReloadPolicies() error {
	seclog.Infof("reload policies")

	return c.LoadPolicies(c.policyProviders, true)
}

func (c *CWS) newRuleOpts() (opts rules.Opts) {
	opts.
		WithSupportedDiscarders(sprobe.SupportedDiscarders).
		WithEventTypeEnabled(c.getEventTypeEnabled()).
		WithReservedRuleIDs(events.AllCustomRuleIDs()).
		WithLogger(seclog.DefaultLogger)
	return
}

func (c *CWS) newEvalOpts() (evalOpts eval.Opts) {
	evalOpts.
		WithConstants(model.SECLConstants).
		WithLegacyFields(model.SECLLegacyFields)
	return evalOpts
}

func (c *CWS) getApproverRuleset(policyProviders []rules.PolicyProvider) (*rules.RuleSet, *multierror.Error) {
	evalOpts := c.newEvalOpts()
	evalOpts.WithVariables(model.SECLVariables)

	opts := c.newRuleOpts()
	opts.WithStateScopes(map[rules.Scope]rules.VariableProviderFactory{
		"process": func() rules.VariableProvider {
			return eval.NewScopedVariables(func(ctx *eval.Context) unsafe.Pointer {
				return unsafe.Pointer(&ctx.Event.(*model.Event).ProcessContext)
			}, nil)
		},
	})

	// approver ruleset
	approverRuleSet := rules.NewRuleSet(&model.Model{}, model.NewDefaultEvent, &opts, &evalOpts)

	// load policies
	loadApproversErrs := approverRuleSet.LoadPolicies(c.policyLoader, c.policyOpts)

	return approverRuleSet, loadApproversErrs
}

// LoadPolicies loads the policies
func (c *CWS) LoadPolicies(policyProviders []rules.PolicyProvider, sendLoadedReport bool) error {
	seclog.Infof("load policies")

	c.Lock()
	defer c.Unlock()

	c.reloading.Store(true)
	defer c.reloading.Store(false)

	rsa := sprobe.NewRuleSetApplier(c.config, c.probe)

	// load policies
	c.policyLoader.SetProviders(policyProviders)

	approverRuleSet, loadApproversErrs := c.getApproverRuleset(policyProviders)
	// non fatal error, just log
	if loadApproversErrs != nil {
		logLoadingErrors("error while loading policies for approvers: %+v", loadApproversErrs)
	}

	approvers, err := approverRuleSet.GetApprovers(sprobe.GetCapababilities())
	if err != nil {
		return err
	}

	opts := c.newRuleOpts()
	opts.
		WithStateScopes(map[rules.Scope]rules.VariableProviderFactory{
			"process": func() rules.VariableProvider {
				scoper := func(ctx *eval.Context) unsafe.Pointer {
					return unsafe.Pointer(ctx.Event.(*model.Event).ProcessCacheEntry)
				}
				return c.probe.GetResolvers().ProcessResolver.NewProcessVariables(scoper)
			},
		})

	evalOpts := c.newEvalOpts()
	evalOpts.WithVariables(model.SECLVariables)

	// standard ruleset
	ruleSet := c.probe.NewRuleSet(&opts, &evalOpts)

	loadErrs := ruleSet.LoadPolicies(c.policyLoader, c.policyOpts)
	if loadApproversErrs.ErrorOrNil() == nil && loadErrs.ErrorOrNil() != nil {
		logLoadingErrors("error while loading policies: %+v", loadErrs)
	}

	// update current policies related module attributes
	c.policiesVersions = getPoliciesVersions(ruleSet)
	c.policyProviders = policyProviders
	c.currentRuleSet.Store(ruleSet)

	// notify listeners
	if c.rulesLoaded != nil {
		c.rulesLoaded(ruleSet, loadApproversErrs)
	}

	// add module as listener for ruleset events
	ruleSet.AddListener(c)

	// analyze the ruleset, push default policies in the kernel and generate the policy report
	report, err := rsa.Apply(ruleSet, approvers)
	if err != nil {
		return err
	}

	// set the rate limiters
	c.rateLimiter.Apply(ruleSet, events.AllCustomRuleIDs())

	// full list of IDs, user rules + custom
	var ruleIDs []rules.RuleID
	ruleIDs = append(ruleIDs, ruleSet.ListRuleIDs()...)
	ruleIDs = append(ruleIDs, events.AllCustomRuleIDs()...)

	c.apiServer.Apply(ruleIDs)

	c.displayReport(report)

	if sendLoadedReport {
		ReportRuleSetLoaded(c.eventSender, c.statsdClient, ruleSet, loadApproversErrs)
		c.policyMonitor.AddPolicies(ruleSet.GetPolicies(), loadApproversErrs)
	}

	return nil
}

// Close the module
func (c *CWS) Stop() {
	signal.Stop(c.sigupChan)
	close(c.sigupChan)

	for _, provider := range c.policyProviders {
		_ = provider.Close()
	}

	// close the policy loader and all the related providers
	if c.policyLoader != nil {
		c.policyLoader.Close()
	}

	if c.selfTester != nil {
		_ = c.selfTester.Close()
	}

	c.cancelFnc()

	c.wg.Wait()
}

// EventDiscarderFound is called by the ruleset when a new discarder discovered
func (c *CWS) EventDiscarderFound(rs *rules.RuleSet, event eval.Event, field eval.Field, eventType eval.EventType) {
	if c.reloading.Load() {
		return
	}

	c.probe.OnNewDiscarder(rs, event.(*model.Event), field, eventType)
}

// HandleEvent is called by the probe when an event arrives from the kernel
func (c *CWS) HandleEvent(event *model.Event) {
	// if the event should have been discarded in kernel space, we don't need to evaluate it
	if event.SavedByActivityDumps {
		return
	}

	if ruleSet := c.GetRuleSet(); ruleSet != nil {
		ruleSet.Evaluate(event)
	}
}

// HandleCustomEvent is called by the probe when an event should be sent to Datadog but doesn't need evaluation
func (c *CWS) HandleCustomEvent(rule *rules.Rule, event *events.CustomEvent) {
	c.eventSender.SendEvent(rule, event, func() []string { return nil }, "")
}

// RuleMatch is called by the ruleset when a rule matches
func (c *CWS) RuleMatch(rule *rules.Rule, event eval.Event) {
	ev := event.(*model.Event)

	// ensure that all the fields are resolved before sending
	ev.FieldHandlers.ResolveContainerID(ev, &ev.ContainerContext)
	ev.FieldHandlers.ResolveContainerTags(ev, &ev.ContainerContext)

	// needs to be resolved here, outside of the callback as using process tree
	// which can be modified during queuing
	service := ev.FieldHandlers.GetProcessServiceTag(ev)

	id := ev.ContainerContext.ID

	extTagsCb := func() []string {
		var tags []string

		// check from tagger
		if service == "" {
			service = c.probe.GetResolvers().TagsResolver.GetValue(id, "service")
		}

		if service == "" {
			service = c.config.HostServiceName
		}

		return append(tags, c.probe.GetResolvers().TagsResolver.Resolve(id)...)
	}

	// send if not selftest related events
	if c.selfTester == nil || !c.selfTester.IsExpectedEvent(rule, event, c.probe) {
		c.eventSender.SendEvent(rule, event, extTagsCb, service)
	}
}

// SendEvent sends an event to the backend after checking that the rate limiter allows it for the provided rule
func (c *CWS) SendEvent(rule *rules.Rule, event Event, extTagsCb func() []string, service string) {
	if c.rateLimiter.Allow(rule.ID) {
		c.apiServer.SendEvent(rule, event, extTagsCb, service)
	} else {
		seclog.Tracef("Event on rule %s was dropped due to rate limiting", rule.ID)
	}
}

// SendProcessEvent sends a process event using the provided EventSender interface
func (c *CWS) SendProcessEvent(data []byte) {
	c.eventSender.SendProcessEventData(data)
}

// SendProcessEventData implements the EventSender interface forwarding a process event to the APIServer
func (c *CWS) SendProcessEventData(data []byte) {
	c.apiServer.SendProcessEvent(data)
}

// HandleActivityDump sends an activity dump to the backend
func (c *CWS) HandleActivityDump(dump *sapi.ActivityDumpStreamMessage) {
	c.apiServer.SendActivityDump(dump)
}

// SendStats send stats
func (c *CWS) SendStats() {
	ackChan := make(chan bool, 1)
	c.sendStatsChan <- ackChan
	<-ackChan
}

func (c *CWS) sendStats() {
	if err := c.probe.SendStats(); err != nil {
		seclog.Debugf("failed to send probe stats: %s", err)
	}
	if err := c.rateLimiter.SendStats(); err != nil {
		seclog.Debugf("failed to send rate limiter stats: %s", err)
	}
	if err := c.apiServer.SendStats(); err != nil {
		seclog.Debugf("failed to send api server stats: %s", err)
	}
}

func (c *CWS) statsSender() {
	/*defer c.wg.Done()

	statsTicker := time.NewTicker(c.config.StatsPollingInterval)
	defer statsTicker.Stop()

	heartbeatTicker := time.NewTicker(15 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case ackChan := <-c.sendStatsChan:
			c.sendStats()
			ackChan <- true
		case <-statsTicker.C:
			c.sendStats()
		case <-heartbeatTicker.C:
			tags := []string{fmt.Sprintf("version:%s", version.AgentVersion)}

			c.RLock()
			for _, version := range c.policiesVersions {
				tags = append(tags, fmt.Sprintf("policies_version:%s", version))
			}
			c.RUnlock()

			if c.config.RuntimeEnabled {
				_ = c.statsdClient.Gauge(metrics.MetricSecurityAgentRuntimeRunning, 1, tags, 1)
			} else if c.config.FIMEnabled {
				_ = c.statsdClient.Gauge(metrics.MetricSecurityAgentFIMRunning, 1, tags, 1)
			}

			// Event monitoring may run independently of CWS products
			if c.config.EventMonitoring {
				_ = c.statsdClient.Gauge(metrics.MetricEventMonitoringRunning, 1, tags, 1)
			}
		case <-c.ctx.Done():
			return
		}
	}*/
}

// GetStats returns statistics about the module
func (c *CWS) GetStats() map[string]interface{} {
	debug := map[string]interface{}{}

	if c.probe != nil {
		debug["probe"] = c.probe.GetDebugStats()
	} else {
		debug["probe"] = "not_running"
	}

	return debug
}

// GetProbe returns the module's probe
func (c *CWS) GetProbe() *sprobe.Probe {
	return c.probe
}

// GetRuleSet returns the set of loaded rules
func (c *CWS) GetRuleSet() (rs *rules.RuleSet) {
	if ruleSet := c.currentRuleSet.Load(); ruleSet != nil {
		return ruleSet.(*rules.RuleSet)
	}
	return nil
}

// SetRulesetLoadedCallback allows setting a callback called when a rule set is loaded
func (c *CWS) SetRulesetLoadedCallback(cb func(rs *rules.RuleSet, err *multierror.Error)) {
	c.rulesLoaded = cb
}

// RunSelfTest runs the self tests
func (c *CWS) RunSelfTest(sendLoadedReport bool) error {
	prevProviders, providers := c.policyProviders, c.policyProviders
	if len(prevProviders) > 0 {
		defer func() {
			if err := c.LoadPolicies(prevProviders, false); err != nil {
				seclog.Errorf("failed to load policies: %s", err)
			}
		}()
	}

	// add selftests as provider
	providers = append(providers, c.selfTester)

	if err := c.LoadPolicies(providers, false); err != nil {
		return err
	}

	success, fails, err := c.selfTester.RunSelfTest()
	if err != nil {
		return err
	}

	seclog.Debugf("self-test results : success : %v, failed : %v", success, fails)

	// send the report
	if c.config.SelfTestSendReport {
		ReportSelfTest(c.eventSender, c.statsdClient, success, fails)
	}

	return nil
}

func logLoadingErrors(msg string, m *multierror.Error) {
	var errorLevel bool
	for _, err := range m.Errors {
		if rErr, ok := err.(*rules.ErrRuleLoad); ok {
			if !errors.Is(rErr.Err, rules.ErrEventTypeNotEnabled) {
				errorLevel = true
			}
		}
	}

	if errorLevel {
		seclog.Errorf(msg, m.Error())
	} else {
		seclog.Warnf(msg, m.Error())
	}
}
