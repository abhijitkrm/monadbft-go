package validation

import (
	"container/list"

	"github.com/abhijitkrm/monadbft-go/cstypes"
)

// lru — a small fixed-capacity LRU over opaque byte-string keys, mirroring
// Rust's lru::LruCache<Vec<u8>, ()>.
type lru struct {
	cap  int
	ll   *list.List // front = most recent; Value = string key
	seen map[string]*list.Element
}

func newLRU(cap int) *lru {
	return &lru{cap: cap, ll: list.New(), seen: make(map[string]*list.Element)}
}

func (c *lru) contains(key string) bool {
	_, ok := c.seen[key]
	return ok
}

func (c *lru) put(key string) {
	if e, ok := c.seen[key]; ok {
		c.ll.MoveToFront(e)
		return
	}
	c.seen[key] = c.ll.PushFront(key)
	if c.ll.Len() > c.cap {
		back := c.ll.Back()
		c.ll.Remove(back)
		delete(c.seen, back.Value.(string))
	}
}

const (
	qcCacheCapacity  = 1000
	tcCacheCapacity  = 1000
	necCacheCapacity = 1000
)

// CertificateCache — Rust CertificateCache: three LRU caches keyed by the
// RLP encoding of each QC/TC/NEC, recording certificates already verified.
type CertificateCache struct {
	qcLRU  *lru
	tcLRU  *lru
	necLRU *lru
}

func NewCertificateCache() *CertificateCache {
	return &CertificateCache{
		qcLRU:  newLRU(qcCacheCapacity),
		tcLRU:  newLRU(tcCacheCapacity),
		necLRU: newLRU(necCacheCapacity),
	}
}

func (c *CertificateCache) CacheValidatedQC(qc *cstypes.QuorumCertificate) {
	c.qcLRU.put(string(qc.EncodeRLP(nil)))
}
func (c *CertificateCache) QCIsCachedValidated(qc *cstypes.QuorumCertificate) bool {
	return c.qcLRU.contains(string(qc.EncodeRLP(nil)))
}

func (c *CertificateCache) CacheValidatedTC(tc *cstypes.TimeoutCertificate) {
	c.tcLRU.put(string(tc.EncodeRLP(nil)))
}
func (c *CertificateCache) TCIsCachedValidated(tc *cstypes.TimeoutCertificate) bool {
	return c.tcLRU.contains(string(tc.EncodeRLP(nil)))
}

func (c *CertificateCache) CacheValidatedNEC(nec *cstypes.NoEndorsementCertificate) {
	c.necLRU.put(string(nec.EncodeRLP(nil)))
}
func (c *CertificateCache) NECIsCachedValidated(nec *cstypes.NoEndorsementCertificate) bool {
	return c.necLRU.contains(string(nec.EncodeRLP(nil)))
}
