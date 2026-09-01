package engine

import (
	"sync"
	"sync/atomic"
)

const (
	bufSmall   = 4 << 10   // 4KB - headers, small bodies
	bufMedium  = 64 << 10  // 64KB - typical JSON responses
	bufLarge   = 256 << 10 // 256KB - large responses
	bufMaxTier = bufLarge
)

type ReusableBuffer struct {
	buf  []byte
	pool *BufferPool
}

func (b *ReusableBuffer) Bytes() []byte { return b.buf }

func (b *ReusableBuffer) Len() int { return len(b.buf) }

func (b *ReusableBuffer) Cap() int { return cap(b.buf) }

func (b *ReusableBuffer) Reset() { b.buf = b.buf[:0] }

func (b *ReusableBuffer) Release() {
	if b.pool == nil {
		return
	}
	b.pool.put(b)
}

type BufferPool struct {
	small  sync.Pool
	medium sync.Pool
	large  sync.Pool

	totalGets        atomic.Int64
	totalReleases    atomic.Int64
	totalAllocations atomic.Int64
	savedAllocations atomic.Int64
	upgradedBuffers  atomic.Int64
}

type PoolStats struct {
	Gets        int64
	Releases    int64
	Allocations int64
	Saved       int64
	Upgrades    int64
}

func NewBufferPool() *BufferPool {
	p := &BufferPool{}
	p.small.New = func() any { return make([]byte, 0, bufSmall) }
	p.medium.New = func() any { return make([]byte, 0, bufMedium) }
	p.large.New = func() any { return make([]byte, 0, bufLarge) }
	return p
}

func (p *BufferPool) Get() *ReusableBuffer {
	return p.GetMinSize(0)
}

func (p *BufferPool) GetMinSize(minSize int) *ReusableBuffer {
	p.totalGets.Add(1)

	var buf []byte
	if minSize <= bufSmall {
		buf = p.small.Get().([]byte)
	} else if minSize <= bufMedium {
		buf = p.medium.Get().([]byte)
	} else if minSize <= bufLarge {
		buf = p.large.Get().([]byte)
	} else {
		p.totalAllocations.Add(1)
		buf = make([]byte, 0, minSize)
		return &ReusableBuffer{buf: buf, pool: p}
	}

	buf = buf[:0]
	return &ReusableBuffer{buf: buf, pool: p}
}

func (p *BufferPool) put(rb *ReusableBuffer) {
	if rb == nil {
		return
	}
	p.totalReleases.Add(1)

	cap := cap(rb.buf)
	switch {
	case cap <= bufSmall:
		rb.buf = rb.buf[:0]
		p.small.Put(rb.buf)
		p.savedAllocations.Add(1)
	case cap <= bufMedium:
		rb.buf = rb.buf[:0]
		p.medium.Put(rb.buf)
		p.savedAllocations.Add(1)
	case cap <= bufLarge:
		rb.buf = rb.buf[:0]
		p.large.Put(rb.buf)
		p.savedAllocations.Add(1)
	default:
		p.upgradedBuffers.Add(1)
	}
	rb.buf = nil
}

func (p *BufferPool) Stats() PoolStats {
	return PoolStats{
		Gets:        p.totalGets.Load(),
		Releases:    p.totalReleases.Load(),
		Allocations: p.totalAllocations.Load(),
		Saved:       p.savedAllocations.Load(),
		Upgrades:    p.upgradedBuffers.Load(),
	}
}

func (p *BufferPool) Reset() {
	p.totalGets.Store(0)
	p.totalReleases.Store(0)
	p.totalAllocations.Store(0)
	p.savedAllocations.Store(0)
	p.upgradedBuffers.Store(0)
}

var DefaultPool = NewBufferPool()

func GetBuffer() *ReusableBuffer            { return DefaultPool.Get() }
func GetBufferMin(size int) *ReusableBuffer { return DefaultPool.GetMinSize(size) }
func ReleaseBuffer(rb *ReusableBuffer)      { rb.Release() }
