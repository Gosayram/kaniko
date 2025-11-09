/*
Copyright 2024 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package image

import (
	"context"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
)

func TestNewLazyImage(t *testing.T) {
	img := empty.Image
	lazyImg, err := NewLazyImage(img)
	if err != nil {
		t.Fatalf("Failed to create lazy image: %v", err)
	}

	if lazyImg == nil {
		t.Fatal("Lazy image is nil")
	}

	if lazyImg.image != img {
		t.Error("Lazy image does not wrap the original image")
	}
}

func TestLazyImageLayers(t *testing.T) {
	img := empty.Image
	lazyImg, err := NewLazyImage(img)
	if err != nil {
		t.Fatalf("Failed to create lazy image: %v", err)
	}

	layers, err := lazyImg.Layers()
	if err != nil {
		t.Fatalf("Failed to get layers: %v", err)
	}

	// Empty image should have no layers
	if len(layers) != 0 {
		t.Errorf("Expected 0 layers for empty image, got %d", len(layers))
	}
}

func TestLazyImageLayerByIndex(t *testing.T) {
	img := empty.Image
	lazyImg, err := NewLazyImage(img)
	if err != nil {
		t.Fatalf("Failed to create lazy image: %v", err)
	}

	ctx := context.Background()
	layer, err := lazyImg.LayerByIndexWithContext(ctx, 0)
	if err == nil && layer != nil {
		t.Error("Expected error for empty image with no layers")
	}
}

func TestLazyImageGetLoadedLayersCount(t *testing.T) {
	img := empty.Image
	lazyImg, err := NewLazyImage(img)
	if err != nil {
		t.Fatalf("Failed to create lazy image: %v", err)
	}

	count := lazyImg.GetLoadedLayersCount()
	if count != 0 {
		t.Errorf("Expected 0 loaded layers, got %d", count)
	}
}

func TestLazyImageGetTotalLayersCount(t *testing.T) {
	img := empty.Image
	lazyImg, err := NewLazyImage(img)
	if err != nil {
		t.Fatalf("Failed to create lazy image: %v", err)
	}

	count := lazyImg.GetTotalLayersCount()
	if count != 0 {
		t.Errorf("Expected 0 total layers for empty image, got %d", count)
	}
}

func TestLazyImageClearLoadedLayers(t *testing.T) {
	img := empty.Image
	lazyImg, err := NewLazyImage(img)
	if err != nil {
		t.Fatalf("Failed to create lazy image: %v", err)
	}

	lazyImg.ClearLoadedLayers()

	count := lazyImg.GetLoadedLayersCount()
	if count != 0 {
		t.Errorf("Expected 0 loaded layers after clear, got %d", count)
	}
}

func TestLazyImageDigest(t *testing.T) {
	img := empty.Image
	lazyImg, err := NewLazyImage(img)
	if err != nil {
		t.Fatalf("Failed to create lazy image: %v", err)
	}

	digest, err := lazyImg.Digest()
	if err != nil {
		t.Fatalf("Failed to get digest: %v", err)
	}

	expectedDigest, err := img.Digest()
	if err != nil {
		t.Fatalf("Failed to get original image digest: %v", err)
	}

	if digest != expectedDigest {
		t.Errorf("Expected digest %s, got %s", expectedDigest.String(), digest.String())
	}
}

func TestLazyImageManifest(t *testing.T) {
	img := empty.Image
	lazyImg, err := NewLazyImage(img)
	if err != nil {
		t.Fatalf("Failed to create lazy image: %v", err)
	}

	manifest, err := lazyImg.Manifest()
	if err != nil {
		t.Fatalf("Failed to get manifest: %v", err)
	}

	if manifest == nil {
		t.Error("Manifest is nil")
	}
}

func TestLazyImageConfigFile(t *testing.T) {
	img := empty.Image
	lazyImg, err := NewLazyImage(img)
	if err != nil {
		t.Fatalf("Failed to create lazy image: %v", err)
	}

	config, err := lazyImg.ConfigFile()
	if err != nil {
		t.Fatalf("Failed to get config file: %v", err)
	}

	if config == nil {
		t.Error("Config file is nil")
	}
}

func TestLazyImageMount(t *testing.T) {
	img := empty.Image
	lazyImg, err := NewLazyImage(img)
	if err != nil {
		t.Fatalf("Failed to create lazy image: %v", err)
	}

	ctx := context.Background()
	err = lazyImg.Mount(ctx, "/tmp/test")
	if err != nil {
		t.Fatalf("Failed to mount: %v", err)
	}
}

func TestLazyImageInterfaceCompliance(t *testing.T) {
	img := empty.Image
	lazyImg, err := NewLazyImage(img)
	if err != nil {
		t.Fatalf("Failed to create lazy image: %v", err)
	}

	// Verify that LazyImage implements v1.Image interface
	var _ v1.Image = lazyImg
}
