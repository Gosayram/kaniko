/*
Copyright 2024 Kaniko Contributors

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

package util

import (
	"bytes"
	"io"
	"sync"
)

// BufferPool provides a pool of reusable buffers for memory optimization
type BufferPool struct {
	pool sync.Pool
}

// NewBufferPool creates a new buffer pool with the specified buffer size
func NewBufferPool(bufferSize int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, bufferSize)
				return &buf
			},
		},
	}
}

// Get returns a buffer from the pool
func (bp *BufferPool) Get() *[]byte {
	return bp.pool.Get().(*[]byte)
}

// Put returns a buffer to the pool
func (bp *BufferPool) Put(buf *[]byte) {
	// Reset the buffer to its original capacity
	*buf = (*buf)[:cap(*buf)]
	bp.pool.Put(buf)
}

// BytesBufferPool provides a pool of reusable bytes.Buffer for string operations
type BytesBufferPool struct {
	pool sync.Pool
}

// NewBytesBufferPool creates a new bytes.Buffer pool
func NewBytesBufferPool() *BytesBufferPool {
	return &BytesBufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				const initialCapacity = 1024 // 1KB
				return bytes.NewBuffer(make([]byte, 0, initialCapacity))
			},
		},
	}
}

// Get returns a bytes.Buffer from the pool
func (bbp *BytesBufferPool) Get() *bytes.Buffer {
	buf := bbp.pool.Get().(*bytes.Buffer)
	buf.Reset() // Clear any previous content
	return buf
}

// Put returns a bytes.Buffer to the pool
func (bbp *BytesBufferPool) Put(buf *bytes.Buffer) {
	// Only return smaller buffers to the pool to avoid memory bloat
	const maxBufferSize = 64 * 1024 // 64KB
	if buf.Cap() <= maxBufferSize {
		buf.Reset()
		bbp.pool.Put(buf)
	}
}

// Buffer pool size constants
const (
	smallBufferSize  = 4 * 1024   // 4KB
	mediumBufferSize = 32 * 1024  // 32KB
	largeBufferSize  = 256 * 1024 // 256KB
)

// Global buffer pools for common operations
var (
	// SmallBufferPool for small operations (4KB)
	SmallBufferPool = NewBufferPool(smallBufferSize)

	// MediumBufferPool for medium operations (32KB)
	MediumBufferPool = NewBufferPool(mediumBufferSize)

	// LargeBufferPool for large operations (256KB)
	LargeBufferPool = NewBufferPool(largeBufferSize)

	// BytesBufferPool for string operations
	GlobalBytesBufferPool = NewBytesBufferPool()
)

// CopyWithBuffer performs io.Copy using a pooled buffer for better memory efficiency
func CopyWithBuffer(dst io.Writer, src io.Reader, pool *BufferPool) (written int64, err error) {
	buf := pool.Get()
	defer pool.Put(buf)

	for {
		nr, er := src.Read(*buf)
		if nr > 0 {
			nw, ew := dst.Write((*buf)[:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = io.ErrShortWrite
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

// CopyFileWithBuffer copies a file using a pooled buffer
func CopyFileWithBuffer(dst io.Writer, src io.Reader) (written int64, err error) {
	return CopyWithBuffer(dst, src, MediumBufferPool)
}

// GetBuffer returns a buffer from the appropriate pool based on size
func GetBuffer(size int) *[]byte {
	switch {
	case size <= 4*1024:
		return SmallBufferPool.Get()
	case size <= 32*1024:
		return MediumBufferPool.Get()
	case size <= 256*1024:
		return LargeBufferPool.Get()
	default:
		// For very large buffers, create a new one
		buf := make([]byte, size)
		return &buf
	}
}

// PutBuffer returns a buffer to the appropriate pool
func PutBuffer(buf *[]byte) {
	size := cap(*buf)
	switch {
	case size <= 4*1024:
		SmallBufferPool.Put(buf)
	case size <= 32*1024:
		MediumBufferPool.Put(buf)
	case size <= 256*1024:
		LargeBufferPool.Put(buf)
		// For very large buffers, let GC handle them
	}
}
