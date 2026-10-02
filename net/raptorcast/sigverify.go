package raptorcast

import (
	"container/list"
	"sync"
	"time"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/types"
)

// signatureVerifier ports parser/signature_verifier.rs: an LRU cache over
// recently verified (signed-over-data → author) plus a token-bucket rate
// limiter on verification work.

const SignatureCacheSize = 10_000

// signatureVerifier verifies RaptorcastChunk-domain signatures.
type signatureVerifier struct {
	mu      sync.Mutex
	cache   *sigLRU
	limiter *tokenBucket
}

func newSignatureVerifier(cacheSize int, ratePerSecond uint32) *signatureVerifier {
	v := &signatureVerifier{}
	if cacheSize > 0 {
		v.cache = newSigLRU(cacheSize)
	}
	if ratePerSecond > 0 {
		v.limiter = newTokenBucket(float64(ratePerSecond), float64(ratePerSecond))
	}
	return v
}

// verifyChunkSignature — Rust verify_signature: cache hit, else
// (bypass ? verify_force : verify), then save_cache.
func (v *signatureVerifier) verifyChunkSignature(sigBytes, signedMessage []byte, bypass bool) (types.NodeId, error) {
	key := string(sigBytes) + "|" + string(signedMessage)
	v.mu.Lock()
	if v.cache != nil {
		if author, ok := v.cache.get(key); ok {
			v.mu.Unlock()
			return author, nil
		}
	}
	if bypass {
		// verify_force: token still counted, result ignored.
		if v.limiter != nil {
			v.limiter.allow()
		}
	} else if v.limiter != nil && !v.limiter.allow() {
		v.mu.Unlock()
		return types.NodeId{}, ErrRateLimited
	}
	v.mu.Unlock()

	sig, err := crypto.SecpSignatureFromBytes(sigBytes)
	if err != nil {
		return types.NodeId{}, ErrInvalidSignature
	}
	pub, err := sig.RecoverPubKey(crypto.DomainRaptorcastChunk, signedMessage)
	if err != nil {
		return types.NodeId{}, ErrInvalidSignature
	}
	author := types.NodeId{PubKey: pub}

	v.mu.Lock()
	if v.cache != nil {
		v.cache.put(key, author)
	}
	v.mu.Unlock()
	return author, nil
}

// sigLRU — small LRU over string keys (same semantics as upstream lru).
type sigLRU struct {
	cap   int
	ll    *list.List
	items map[string]*list.Element
}

type sigEntry struct {
	key    string
	author types.NodeId
}

func newSigLRU(capacity int) *sigLRU {
	return &sigLRU{cap: capacity, ll: list.New(), items: make(map[string]*list.Element)}
}

func (l *sigLRU) get(key string) (types.NodeId, bool) {
	e, ok := l.items[key]
	if !ok {
		return types.NodeId{}, false
	}
	l.ll.MoveToFront(e)
	return e.Value.(sigEntry).author, true
}

func (l *sigLRU) put(key string, author types.NodeId) {
	if e, ok := l.items[key]; ok {
		l.ll.MoveToFront(e)
		e.Value = sigEntry{key, author}
		return
	}
	e := l.ll.PushFront(sigEntry{key, author})
	l.items[key] = e
	if l.ll.Len() > l.cap {
		back := l.ll.Back()
		if back != nil {
			delete(l.items, back.Value.(sigEntry).key)
			l.ll.Remove(back)
		}
	}
}

// tokenBucket — governor-equivalent per-second rate limiter.
type tokenBucket struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
}

func newTokenBucket(ratePerSecond, burst float64) *tokenBucket {
	return &tokenBucket{
		rate:     ratePerSecond,
		capacity: burst,
		tokens:   burst,
		last:     time.Now(),
	}
}

func (t *tokenBucket) allow() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(t.last).Seconds()
	t.last = now
	t.tokens += elapsed * t.rate
	if t.tokens > t.capacity {
		t.tokens = t.capacity
	}
	if t.tokens < 1 {
		return false
	}
	t.tokens--
	return true
}
