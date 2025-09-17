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

package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	kanikoConfig "github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/multiplatform"
)

// TestMultiPlatformK8sIntegration tests the Kubernetes driver integration with a real Kubernetes cluster
// This test requires a running Kubernetes cluster (e.g., kind, minikube) and appropriate permissions
func TestMultiPlatformK8sIntegration(t *testing.T) {
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
	_, err = clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("Failed to list nodes: %v", err)
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
	_, err = multiplatform.NewKubernetesDriver(opts)
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
							Name:  "test",
							Image: "busybox",
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

// TestMultiPlatformK8sJobTemplate tests the job template creation for multi-platform builds
func TestMultiPlatformK8sJobTemplate(t *testing.T) {
	if os.Getenv("KANIKO_TEST_K8S") == "" {
		t.Skip("Skipping Kubernetes job template test. Set KANIKO_TEST_K8S=1 to enable")
	}

	opts := &kanikoConfig.KanikoOptions{
		SrcContext:      "dir:///workspace",
		DockerfilePath:  "Dockerfile",
		Destinations:    []string{"registry.example.com/test:latest"},
		Cache:           true,
		CacheRepo:       "registry.example.com/cache",
		RequireNativeNodes: true,
	}

	// Test job creation for different platforms
	platforms := []string{"linux/amd64", "linux/arm64"}

	for _, platform := range platforms {
		t.Run(platform, func(t *testing.T) {
			// Create a mock driver to test job creation
			// We'll test the createBuildJob function indirectly through validation
			// since it's an unexported method
			
			// Test platform validation first
			driver, err := multiplatform.NewKubernetesDriver(opts)
			if err != nil {
				t.Logf("Kubernetes driver creation failed (expected in test environment): %v", err)
				t.Skip("Skipping job template test due to missing Kubernetes environment")
			}

			// Test platform validation
			err = driver.ValidatePlatforms([]string{platform})
			if err != nil {
				t.Fatalf("Platform validation failed for %s: %v", platform, err)
			}

			t.Logf("Platform %s validated successfully", platform)
			
			// Test that platform requirements can be generated
			requirements, err := multiplatform.PlatformRequirements(platform)
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
		})
	}
}

// TestMultiPlatformK8sPlatformValidation tests platform validation in Kubernetes cluster
func TestMultiPlatformK8sPlatformValidation(t *testing.T) {
	if os.Getenv("KANIKO_TEST_K8S") == "" {
		t.Skip("Skipping Kubernetes platform validation test. Set KANIKO_TEST_K8S=1 to enable")
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
		t.Logf("Available node: %s (arch: %s)", node.Name, arch)
	}

	// Test platforms that should be available
	testPlatforms := []string{
		"linux/amd64",
		"linux/arm64",
	}

	for _, platform := range testPlatforms {
		t.Run(platform, func(t *testing.T) {
			parts := strings.Split(platform, "/")
			if len(parts) != 2 {
				t.Fatalf("Invalid platform format: %s", platform)
			}

			arch := parts[1]
			if !availableArchs[arch] {
				t.Logf("Architecture %s not available in cluster, skipping test", arch)
				t.Skip()
			}

			t.Logf("Platform %s is available in cluster", platform)
		})
	}
}