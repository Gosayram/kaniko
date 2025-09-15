/*
Copyright 2018 Google LLC

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

package buildcontext

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	s3manager "github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	kConfig "github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/constants"
	"github.com/Gosayram/kaniko/pkg/util"
	"github.com/Gosayram/kaniko/pkg/util/bucket"
)

// S3 unifies calls to download and unpack the build context.
type S3 struct {
	context string
}

// UnpackTarFromBuildContext download and untar a file from s3
func (s *S3) UnpackTarFromBuildContext() (string, error) {
	bucketName, item, err := bucket.GetNameAndFilepathFromURI(s.context)
	if err != nil {
		return "", fmt.Errorf("getting bucketname and filepath from context: %w", err)
	}

	endpoint := os.Getenv(constants.S3EndpointEnv)
	forcePath := strings.ToLower(os.Getenv(constants.S3ForcePathStyle)) == "true"

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return bucketName, err
	}
	client := s3.NewFromConfig(cfg, func(options *s3.Options) {
		if endpoint != "" {
			options.UsePathStyle = forcePath
			options.BaseEndpoint = aws.String(endpoint)
		}
	})
	downloader := s3manager.NewDownloader(client)
	directory := kConfig.BuildContextDir
	tarPath := filepath.Join(directory, constants.ContextTar)
	if mkdirErr := os.MkdirAll(directory, 0o750); mkdirErr != nil {
		return directory, err
	}
	// Ensure tarPath stays within the intended directory
	if !strings.HasPrefix(filepath.Clean(tarPath), directory) {
		return directory, fmt.Errorf("potential path traversal attempt - "+
			"tarPath %s not within directory %s", tarPath, directory)
	}
	file, err := os.Create(filepath.Clean(tarPath))
	if err != nil {
		return directory, err
	}
	_, downloadErr := downloader.Download(context.TODO(), file,
		&s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(item),
		})
	if downloadErr != nil {
		return directory, downloadErr
	}

	return directory, util.UnpackCompressedTar(tarPath, directory)
}
