/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by default law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package multiplatform

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/utils/ptr"

	"github.com/Gosayram/kaniko/pkg/config"
)

const (
	expectedPlatformParts = 2 // platform format should be "os/arch"
	defaultTimeout        = 30 * time.Minute
	pollInterval          = 10 * time.Second
)

// KubernetesDriver implements the Driver interface for Kubernetes-based multi-platform builds
type KubernetesDriver struct {
	opts      *config.KanikoOptions
	config    *rest.Config
	client    *kubernetes.Clientset
	namespace string
}

// NewKubernetesDriver creates a new Kubernetes driver instance
func NewKubernetesDriver(opts *config.KanikoOptions) (*KubernetesDriver, error) {
	// Create in-cluster config
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create in-cluster config: %w", err)
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Get namespace (default to current pod namespace)
	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	return &KubernetesDriver{
		opts:      opts,
		config:    kubeConfig,
		client:    clientset,
		namespace: namespace,
	}, nil
}

// ValidatePlatforms validates that the requested platforms can be built in the Kubernetes cluster
func (d *KubernetesDriver) ValidatePlatforms(platforms []string) error {
	if len(platforms) == 0 {
		return fmt.Errorf("no platforms specified")
	}

	if d.opts.RequireNativeNodes {
		// Check if cluster has nodes for all requested architectures
		nodes, err := d.client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list nodes: %w", err)
		}

		availableArchs := make(map[string]bool)
		for i := range nodes.Items {
			arch := nodes.Items[i].Status.NodeInfo.Architecture
			availableArchs[arch] = true
		}

		for _, platform := range platforms {
			parts := strings.Split(platform, "/")
			if len(parts) != expectedPlatformParts {
				return fmt.Errorf("invalid platform format: %s", platform)
			}
			arch := parts[1]
			if !availableArchs[arch] {
				return fmt.Errorf("no nodes available for architecture: %s", arch)
			}
		}
		logrus.Infof("All required architectures available in cluster: %v", platforms)
	}

	for _, platform := range platforms {
		parts := strings.Split(platform, "/")
		if len(parts) != expectedPlatformParts {
			return fmt.Errorf("invalid platform format: %s (expected os/arch)", platform)
		}

		osName, arch := parts[0], parts[1]
		if osName == "" || arch == "" {
			return fmt.Errorf("invalid platform format: %s (both os and arch must be specified)", platform)
		}

		// Basic platform validation
		if !isSupportedOS(osName) {
			return fmt.Errorf("unsupported operating system: %s", osName)
		}
		if !isSupportedArchitecture(arch) {
			return fmt.Errorf("unsupported architecture: %s", arch)
		}
	}

	return nil
}

// ExecuteBuilds creates Kubernetes Jobs for each platform and waits for completion
func (d *KubernetesDriver) ExecuteBuilds(ctx context.Context, platforms []string) (map[string]string, error) {
	digests := make(map[string]string)

	for _, platform := range platforms {
		job, err := d.createBuildJob(platform)
		if err != nil {
			return nil, fmt.Errorf("failed to create job for platform %s: %w", platform, err)
		}

		// Create the job
		createdJob, err := d.client.BatchV1().Jobs(d.namespace).Create(ctx, job, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to create job for platform %s: %w", platform, err)
		}

		logrus.Infof("Created build job %s for platform %s", createdJob.Name, platform)

		// Wait for job completion
		digest, err := d.waitForJobCompletion(ctx, createdJob.Name, platform)
		if err != nil {
			return nil, fmt.Errorf("job failed for platform %s: %w", platform, err)
		}

		digests[platform] = digest
	}

	return digests, nil
}

// Cleanup performs cleanup operations for Kubernetes driver
func (d *KubernetesDriver) Cleanup() error {
	if d.client == nil {
		return fmt.Errorf("kubernetes client not initialized")
	}

	// Cleanup: delete all jobs created by this driver
	jobs, err := d.client.BatchV1().Jobs(d.namespace).List(context.Background(), metav1.ListOptions{
		LabelSelector: "app=kaniko-multiarch-builder",
	})
	if err != nil {
		return fmt.Errorf("failed to list jobs for cleanup: %w", err)
	}

	for i := range jobs.Items {
		err := d.client.BatchV1().Jobs(d.namespace).Delete(context.Background(), jobs.Items[i].Name, metav1.DeleteOptions{})
		if err != nil {
			logrus.Warnf("Failed to delete job %s: %v", jobs.Items[i].Name, err)
		} else {
			logrus.Infof("Deleted job %s", jobs.Items[i].Name)
		}
	}

	logrus.Info("Kubernetes driver cleanup completed")
	return nil
}

// isSupportedOS checks if the operating system is supported
func isSupportedOS(osName string) bool {
	supportedOS := map[string]bool{
		"linux":   true,
		"windows": true,
		"darwin":  true,
	}
	return supportedOS[osName]
}

// isSupportedArchitecture checks if the architecture is supported
func isSupportedArchitecture(arch string) bool {
	supportedArch := map[string]bool{
		"amd64": true,
		"arm64": true,
		"arm":   true,
		"386":   true,
		"ppc64": true,
		"s390x": true,
	}
	return supportedArch[arch]
}

// createBuildJob creates a Kubernetes Job for a specific platform
func (d *KubernetesDriver) createBuildJob(platform string) (*batchv1.Job, error) {
	parts := strings.Split(platform, "/")
	if len(parts) != expectedPlatformParts {
		return nil, fmt.Errorf("invalid platform format: %s", platform)
	}

	osName, arch := parts[0], parts[1]
	jobName := fmt.Sprintf("kaniko-build-%s-%s", strings.ReplaceAll(osName, ".", "-"), strings.ReplaceAll(arch, ".", "-"))

	// Build kaniko args
	args := []string{
		"--context=" + d.opts.SrcContext,
		"--dockerfile=" + d.opts.DockerfilePath,
		"--destination=" + d.getDestinationForPlatform(platform),
		"--custom-platform=" + platform,
		"--digest-file=/output/digest.txt",
	}

	// Add additional options
	if d.opts.Cache {
		args = append(args, "--cache=true")
	}
	if d.opts.CacheRepo != "" {
		args = append(args, "--cache-repo="+d.opts.CacheRepo)
	}
	if d.opts.CacheTTL != 0 {
		args = append(args, fmt.Sprintf("--cache-ttl=%s", d.opts.CacheTTL))
	}

	// Assume registry secret name from env or default "dockerconfigjson"
	registrySecret := os.Getenv("KANIKO_REGISTRY_SECRET")
	if registrySecret == "" {
		registrySecret = "dockerconfigjson"
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: d.namespace,
			Labels: map[string]string{
				"app": "kaniko-multiarch-builder",
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: ptr.To[int32](0),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "kaniko-builder", // From plan example
					RestartPolicy:      corev1.RestartPolicyNever,
					NodeSelector: map[string]string{
						"kubernetes.io/arch": arch,
						"kubernetes.io/os":   osName,
					},
					Containers: []corev1.Container{
						{
							Name:  "kaniko",
							Image: "gcr.io/kaniko-project/executor:latest",
							Args:  args,
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("2Gi"),
									corev1.ResourceCPU:    resource.MustParse("1"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("4Gi"),
									corev1.ResourceCPU:    resource.MustParse("2"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "docker-config",
									MountPath: "/kaniko/.docker/",
									ReadOnly:  true,
								},
								{
									Name:      "output",
									MountPath: "/output",
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "DOCKER_CONFIG",
									Value: "/kaniko/.docker/",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "docker-config",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: registrySecret,
								},
							},
						},
						{
							Name: "output",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
		},
	}

	return job, nil
}

// waitForJobCompletion waits for a Kubernetes Job to complete and returns the digest
func (d *KubernetesDriver) waitForJobCompletion(ctx context.Context, jobName, platform string) (string, error) {
	if d.client == nil {
		return "", fmt.Errorf("kubernetes client not initialized")
	}

	err := wait.PollUntilContextTimeout(ctx, pollInterval, defaultTimeout, true, func(ctx context.Context) (bool, error) {
		job, err := d.client.BatchV1().Jobs(d.namespace).Get(ctx, jobName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if job.Status.Succeeded > 0 {
			return true, nil
		}

		if job.Status.Failed > 0 {
			return false, fmt.Errorf("job %s failed", jobName)
		}

		return false, nil
	})

	if err != nil {
		return "", fmt.Errorf("job %s did not complete successfully: %w", jobName, err)
	}

	// Read digest from pod logs
	return d.readDigestFromPod(ctx, jobName, platform)
}

// readDigestFromPod reads the digest from the completed pod's output
func (d *KubernetesDriver) readDigestFromPod(ctx context.Context, jobName, platform string) (string, error) {
	if d.client == nil {
		return "", fmt.Errorf("kubernetes client not initialized")
	}

	pods, err := d.client.CoreV1().Pods(d.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("job-name=%s", jobName),
	})
	if err != nil {
		return "", fmt.Errorf("failed to list pods for job %s: %w", jobName, err)
	}

	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pods found for job %s", jobName)
	}

	// Assume first (and only) pod from job
	pod := &pods.Items[0]
	if pod.Status.Phase != corev1.PodSucceeded {
		return "", fmt.Errorf("pod %s/%s not succeeded: %s", d.namespace, pod.Name, pod.Status.Phase)
	}

	// Exec into pod to cat /output/digest.txt
	req := d.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(pod.Name).
		Namespace(d.namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Command: []string{"cat", "/output/digest.txt"},
			Stdin:   false,
			Stdout:  true,
			Stderr:  true,
			TTY:     false,
		}, runtime.NewParameterCodec(scheme.Scheme))

	exec, err := remotecommand.NewSPDYExecutor(d.config, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("failed to create exec: %w", err)
	}

	var stdout, stderr bytes.Buffer
	err = exec.Stream(remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	})
	if err != nil {
		return "", fmt.Errorf("exec failed: %w; stderr: %s", err, stderr.String())
	}

	digest := strings.TrimSpace(stdout.String())
	if digest == "" {
		return "", fmt.Errorf("empty digest from /output/digest.txt")
	}

	if !strings.HasPrefix(digest, "sha256:") {
		return "", fmt.Errorf("invalid digest format: %s", digest)
	}

	logrus.Infof("Retrieved digest for %s: %s", platform, digest)
	return digest, nil
}

// getDigestFilename returns the expected filename for a platform's digest
func (d *KubernetesDriver) getDigestFilename(platform string) string {
	return strings.ReplaceAll(platform, "/", "-") + ".digest"
}

// getDestinationForPlatform returns the destination registry with platform suffix
func (d *KubernetesDriver) getDestinationForPlatform(platform string) string {
	if len(d.opts.Destinations) == 0 {
		return ""
	}

	// For multi-platform builds, we typically use the same destination for all platforms
	// and let the coordinator handle the index creation
	destination := d.opts.Destinations[0]
	if strings.Contains(destination, ":") {
		// Add platform suffix to tag
		parts := strings.Split(destination, ":")
		if len(parts) == expectedPlatformParts {
			return fmt.Sprintf("%s:%s-%s", parts[0], parts[1], strings.ReplaceAll(platform, "/", "-"))
		}
	}
	return destination
}

// PlatformRequirements returns the Kubernetes node selector requirements for a platform
func PlatformRequirements(platform string) (map[string]string, error) {
	parts := strings.Split(platform, "/")
	if len(parts) != expectedPlatformParts {
		return nil, fmt.Errorf("invalid platform format: %s", platform)
	}

	osName, arch := parts[0], parts[1]

	return map[string]string{
		"kubernetes.io/arch": arch,
		"kubernetes.io/os":   osName,
	}, nil
}

// SupportedPlatforms returns the list of platforms supported by Kubernetes driver
func SupportedPlatforms() []string {
	return []string{
		"linux/amd64",
		"linux/arm64",
		"linux/arm",
		"linux/ppc64",
		"linux/s390x",
		"windows/amd64",
		"windows/arm64",
		"darwin/amd64",
		"darwin/arm64",
	}
}
