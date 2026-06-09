package ca

import (
	"context"
	"sync/atomic"
)

// SerialAllocator hands out unique, increasing certificate serial numbers.
// Serials are recorded for audit (ADR-007) and used by revocation lists. The
// in-memory CounterAllocator below is for dev/testing; the production
// allocator is backed by a PostgreSQL sequence so serials remain unique and
// monotonic across restarts and replicas (wired with persistence in Phase 3).
type SerialAllocator interface {
	Next(ctx context.Context) (uint64, error)
}

// CounterAllocator is an in-process monotonic allocator. Serials reset on
// restart, so it must not be used in production.
type CounterAllocator struct {
	n atomic.Uint64
}

// NewCounterAllocator returns an allocator whose first Next() returns start+1.
func NewCounterAllocator(start uint64) *CounterAllocator {
	c := &CounterAllocator{}
	c.n.Store(start)
	return c
}

// Next returns the next serial number.
func (c *CounterAllocator) Next(_ context.Context) (uint64, error) {
	return c.n.Add(1), nil
}

var _ SerialAllocator = (*CounterAllocator)(nil)
