// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver

// Package mutate implements the mutations needed by the auto-instrumentation feature.
package mutate

import (
	"errors"
	"fmt"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"gopkg.in/yaml.v2"

	"github.com/DataDog/datadog-agent/pkg/config"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	k8s "k8s.io/client-go/kubernetes"
)

func InjectAgentSidecar(rawPod []byte, _ string, ns string, _ *authenticationv1.UserInfo, dc dynamic.Interface, _ k8s.Interface) ([]byte, error) {
	return mutate(rawPod, ns, injectAgentSidecar, dc)
}

func injectAgentSidecar(pod *corev1.Pod, _ string, _ dynamic.Interface) error {
	if pod == nil {
		return errors.New("cannot inject sidecar into nil pod")
	}
	log.Info("Injecting side car", "pod", pod)

	for i, _ := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == "datadog-agent-injected" {
			log.Info("sidecar already injected, skipping")
			return nil
		}
	}
	allSettings := config.Datadog.AllSettings()
	log.Info("Reading config", "allSettings", allSettings)
	sidecar := agentSidecarFromConfig()
	pod.Spec.Containers = append(pod.Spec.Containers, *sidecar)
	log.Info("Injecting side car; resulting pod", "pod", pod)

	return nil
}

func agentSidecarFromConfig() *corev1.Container {
	yamlContent := config.Datadog.GetString("admission_controller.agent_sidecar.sidecaryaml")
	yamlContentCM := config.Datadog.GetString("admission_controller.agent_sidecar.sidecaryaml_cm")
	log.Info("Reading side car", "yaml", yamlContent, "yaml_cm", yamlContentCM)

	var containers []corev1.Container
	err := yaml.Unmarshal([]byte(yamlContent), &containers)
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}
	log.Info("Umarshalled side car", "container", containers[0])
	agentContainer := containers[0]
	for i, _ := range agentContainer.Env {
		if agentContainer.Env[i].Name == "DD_API_KEY" {
			agentContainer.Env[i].ValueFrom = &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key: "api-key",
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "datadog-agent-linux",
					},
				},
			}
		} else if agentContainer.Env[i].Name == "DD_CLUSTER_AGENT_AUTH_TOKEN" {
			agentContainer.Env[i].ValueFrom = &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					Key: "token",
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "datadog-cluster-agent",
					},
				},
			}
		} else if agentContainer.Env[i].Name == "DD_KUBERNETES_KUBELET_NODENAME" {
			agentContainer.Env[i].ValueFrom = &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					APIVersion: "v1",
					FieldPath:  "spec.nodeName",
				},
			}
		}
	}

	return &containers[0]
}

// Default when side car injection is enabled
// `agent_sidecar.sidecaryaml`
// Two way to inject side car template
// 1) env var, 2) config map
//
// we use config map for sidecar template
//
// Helm     -> env var or CM
// Operator  -> env var; check in Operator (CustomConfigSpec ksm core)
// DCA Deployment -> env var or CM
func agentSidecar() *corev1.Container {
	agentContainer := &corev1.Container{
		// DD_API_KEY
		// DD_SITE
		// DD_CLUSTER_NAME
		// DD_EKS_FARGATE
		// DD_PROCESS_CONFIG_PROCESS_COLLECTION_ENABLED
		// DD_KUBERNETES_KUBELET_NODENAME
		// DD_HEALTH_PORT
		// DD_CLUSTER_AGENT_ENABLED
		// DD_CLUSTER_AGENT_AUTH_TOKEN
		// DD_CLUSTER_AGENT_URL
		// DD_ORCHESTRATOR_EXPLORER_ENABLED

		Env: []corev1.EnvVar{
			{
				Name: "DD_API_KEY",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						Key: "api-key",
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "datadog-agent-linux",
						},
					},
				},
			},
			{
				Name:  "DD_SITE",
				Value: "datadoghq.com",
			},
			{
				Name:  "DD_CLUSTER_NAME",
				Value: config.Datadog.GetString("cluster_name"),
			},
			{
				Name:  "DD_EKS_FARGATE",
				Value: "true",
			},
			{
				Name:  "DD_PROCESS_CONFIG_PROCESS_COLLECTION_ENABLED",
				Value: "true",
			},
			{
				Name: "DD_KUBERNETES_KUBELET_NODENAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						APIVersion: "v1",
						FieldPath:  "spec.nodeName",
					},
				},
			},
			{
				Name:  "DD_HEALTH_PORT",
				Value: "5555",
			},
			{
				Name:  "DD_CLUSTER_AGENT_ENABLED",
				Value: "",
			},
			{
				Name: "DD_CLUSTER_AGENT_AUTH_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						Key: "token",
						LocalObjectReference: corev1.LocalObjectReference{
							Name: "datadog-agent-linux-cluster-agent",
						},
					},
				},
			},
			{
				Name:  "DD_CLUSTER_AGENT_URL",
				Value: "https://datadog-agent-linux-cluster-agent.fargate.svc.cluster.local:5005",
			},
			{
				Name:  "DD_ORCHESTRATOR_EXPLORER_ENABLED",
				Value: "true",
			},
		},
		Image:           "public.ecr.aws/datadog/agent:7.47.1",
		ImagePullPolicy: corev1.PullIfNotPresent,

		LivenessProbe: &corev1.Probe{
			FailureThreshold:    2,
			InitialDelaySeconds: 15,
			PeriodSeconds:       15,
			SuccessThreshold:    1,
			TimeoutSeconds:      5,
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/live",
					Port: intstr.IntOrString{
						IntVal: 5555,
					},
					Scheme: corev1.URISchemeHTTP,
				},
			},
		},

		ReadinessProbe: &corev1.Probe{
			FailureThreshold:    6,
			InitialDelaySeconds: 15,
			PeriodSeconds:       15,
			SuccessThreshold:    1,
			TimeoutSeconds:      5,
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/ready",
					Port: intstr.IntOrString{
						IntVal: 5555,
					},
					Scheme: corev1.URISchemeHTTP,
				},
			},
		},

		Name: "datadog-agent-injected",
	}

	return agentContainer
}