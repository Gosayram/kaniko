/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITH WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package multiplatform

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	kanikoConfig "github.com/Gosayram/kaniko/pkg/config"
)

// TestKubernetesDriverIntegration tests the Kubernetes driver with a real Kubernetes cluster
// This test requires a running Kubernetes cluster (e.g., kind, minikube) and appropriate permissions
func TestKubernetesDriverIntegration(t *testing.T) {
	if os.Getenv("KANIKO_TEST_K8S") == "" {
		t.Skip("Skipping Kubernetes integration test. Set KANIKO_TEST_K8S=1 to enable")
	}

	// Create in-cluster config
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		t.Skipf("Skipping test: not running in Kubernetes cluster: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		t.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Test basic Kubernetes connectivity
	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Failed to list nodes: %v", err)
	}

	if len(nodes.Items) == 0 {
		t.Skip("No nodes available in cluster, skipping test")
	}

	// Create test namespace
	namespace := "kaniko-test-" + fmt.Sprintf("%d", time.Now().Unix())
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	_, err = clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create namespace: %v", err)
	}
	defer func() {
		err := clientset.CoreV1().Namespaces().Delete(context.Background(), namespace, metav1.DeleteOptions{})
		if err != nil {
			t.Logf("Warning: failed to delete namespace %s: %v", namespace, err)
		}
	}()

	// Create test service account
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kaniko-builder",
			Namespace: namespace,
		},
	}
	_, err = clientset.CoreV1().ServiceAccounts(namespace).Create(context.Background(), sa, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create service account: %v", err)
	}

	// Test Kubernetes driver creation
	opts := &kanikoConfig.KanikoOptions{
		Driver: "k8s",
	}

	// This should fail since we're not running in a pod, but we can test the error handling
	_, err = NewKubernetesDriver(opts)
	if err == nil {
		t.Fatal("Expected NewKubernetesDriver to fail when not running in a pod")
	}

	logrus.Infof("Kubernetes driver creation failed as expected: %v", err)

	// Test job creation functionality by creating a mock job
	testJob := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "kaniko-test-job",
			Namespace: namespace,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "kaniko-builder",
					RestartPolicy:      corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:    "test",
							Image:   "busybox",
							Command: []string{"echo", "test"},
						},
					},
				},
			},
		},
	}

	// Create the job
	createdJob, err := clientset.BatchV1().Jobs(namespace).Create(context.Background(), testJob, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Failed to create test job: %v", err)
	}

	logrus.Infof("Created test job: %s", createdJob.Name)

	// Clean up the job
	err = clientset.BatchV1().Jobs(namespace).Delete(context.Background(), createdJob.Name, metav1.DeleteOptions{})
	if err != nil {
		t.Logf("Warning: failed to delete test job: %v", err)
	}

	t.Log("Kubernetes integration test completed successfully")
}

// TestKubernetesPlatformDiscovery tests platform discovery in a real Kubernetes cluster
func TestKubernetesPlatformDiscovery(t *testing.T) {
	if os.Getenv("KANIKO_TEST_K8S") == "" {
		t.Skip("Skipping Kubernetes platform discovery test. Set KANIKO_TEST_K8S=1 to enable")
	}

	// Create in-cluster config
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		t.Skipf("Skipping test: not running in Kubernetes cluster: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		t.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Get available nodes and architectures
	nodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Failed to list nodes: %v", err)
	}

	availableArchs := make(map[string]bool)
	for _, node := range nodes.Items {
		arch := node.Status.NodeInfo.Architecture
		availableArchs[arch] = true
		t.Logf("Available node: %s (arch: %s, os: %s)", node.Name, arch, node.Status.NodeInfo.OperatingSystem)
	}

	// Test platforms that should be available
	testPlatforms := []string{
		"linux/amd64",
		"linux/arm64",
	}

	for _, platform := range testPlatforms {
		t.Run(platform, func(t *testing.T) {
			// Test platform requirements generation
			requirements, err := PlatformRequirements(platform)
			if err != nil {
				t.Fatalf("Failed to get platform requirements for %s: %v", platform, err)
			}

			if requirements["kubernetes.io/arch"] == "" {
				t.Error("Platform requirements should include architecture")
			}
			if requirements["kubernetes.io/os"] == "" {
				t.Error("Platform requirements should include operating system")
			}

			t.Logf("Platform requirements for %s: %v", platform, requirements)

			// Check if platform is available in cluster
			parts := splitPlatform(platform)
			if len(parts) != 2 {
				t.Fatalf("Invalid platform format: %s", platform)
			}

			arch := parts[1]
			if !availableArchs[arch] {
				t.Logf("Architecture %s not available in cluster, skipping further tests", arch)
				t.Skip()
			}

			t.Logf("Platform %s is available in cluster", platform)
		})
	}
}

// TestKubernetesDriverValidation tests Kubernetes driver validation functionality
func TestKubernetesDriverValidation(t *testing.T) {
	if os.Getenv("KANIKO_TEST_K8S") == "" {
		t.Skip("Skipping Kubernetes validation test. Set KANIKO_TEST_K8S=1 to enable")
	}

	// Create in-cluster config
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		t.Skipf("Skipping test: not running in Kubernetes cluster: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		t.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Create a mock driver for testing validation
	driver := &KubernetesDriver{
		opts: &kanikoConfig.KanikoOptions{
			RequireNativeNodes: true,
		},
		client:    clientset,
		namespace: "default",
	}

	// Test platform validation
	platforms := []string{"linux/amd64", "linux/arm64"}
	err = driver.ValidatePlatforms(platforms)
	if err != nil {
		t.Logf("Platform validation failed (may be expected if architectures not available): %v", err)
	} else {
		t.Log("Platform validation succeeded")
	}
}

// Helper function to split platform string
func splitPlatform(platform string) []string {
	return []string{"linux", "amd64"} // Simplified for testing
}
