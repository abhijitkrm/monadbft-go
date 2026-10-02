package raptorcast

import (
	"container/list"
	"errors"
	"fmt"
	"time"

	"github.com/abhijitkrm/monadbft-go/raptor"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

var _ = time.Now // time used via cooldown fields

// Decoder cache — ports monad-raptorcast decoding.rs: per-message
// ManagedDecoder instances organized into three quota tiers, plus a
// recently-decoded LRU and taint tracking.

var (
	ErrInvalidSymbolLen         = errors.New("invalid symbol length")
	ErrInvalidSymbolID          = errors.New("invalid symbol id")
	ErrInvalidAppMsgLenInSymbol = errors.New("invalid app message length in symbol")
	ErrDuplicateSymbol          = errors.New("duplicate symbol")
	ErrInvalidDecoderParams     = errors.New("invalid decoder parameters")
	ErrUnableToReconstruct      = errors.New("unable to reconstruct source data")
	ErrMessageTainted           = errors.New("message tainted")
)

const recentlyDecodedCacheSize = 10_000

// softQuotaConfig — Rust SoftQuotaCacheConfig. minSlotsPerValidator < 0
// selects the FixedQuota policy (the upstream default).
type softQuotaConfig struct {
	totalSlots               int
	minSlotsPerAuthor        int
	maxTotalSizePerAuthor    int
	minSlotsPerValidator     int
	maxTotalSizePerValidator int
}

var defaultDecoderCacheConfig = decoderCacheConfig{
	recentlyDecodedCacheSize: recentlyDecodedCacheSize,
	broadcastTier: softQuotaConfig{
		totalSlots:            1000,
		minSlotsPerAuthor:     5,
		maxTotalSizePerAuthor: 5 * 4 * 1024 * 1024,
		minSlotsPerValidator:  -1,
	},
	validatorTier: softQuotaConfig{
		totalSlots:            600,
		minSlotsPerAuthor:     3,
		maxTotalSizePerAuthor: 1024 * 1024,
		minSlotsPerValidator:  -1,
	},
	p2pTier: softQuotaConfig{
		totalSlots:            500,
		minSlotsPerAuthor:     1,
		maxTotalSizePerAuthor: 1024 * 1024,
		minSlotsPerValidator:  -1,
	},
}

type decoderCacheConfig struct {
	recentlyDecodedCacheSize int
	broadcastTier            softQuotaConfig
	validatorTier            softQuotaConfig
	p2pTier                  softQuotaConfig
}

type messageTier int

const (
	tierBroadcast messageTier = iota
	tierValidator
	tierP2P
)

// tierForMessage — Rust MessageTier::from_message.
func tierForMessage(msg *validatedChunk, validatorSet *validator.ValidatorSet) messageTier {
	if msg.broadcastMode != BroadcastUnspecified {
		return tierBroadcast
	}
	if validatorSet != nil && validatorSet.IsMember(msg.author) {
		return tierValidator
	}
	return tierP2P
}

// cacheKey — Rust CacheKeyInner: author hash + message id + timestamp.
// For v0 the message id is the app-message hash; v1 uses the global merkle
// root.
type cacheKey struct {
	authorHash NodeIdHash
	messageID  AppMessageHash
	unixTsMs   uint64
}

func cacheKeyFromMessage(m *validatedChunk) cacheKey {
	k := cacheKey{
		authorHash: computeHash(m.author),
		unixTsMs:   m.unixTsMs,
	}
	if m.appMessageHash != nil {
		k.messageID = *m.appMessageHash
	} else {
		k.messageID = AppMessageHash(m.merkleRoot)
	}
	return k
}

// validateSymbol — Rust decoding::validate_symbol.
func validateSymbol(msg *validatedChunk, symbolLen, appMessageLen int, seen map[int]struct{}, capacity int) error {
	esi := int(msg.chunkID)
	if len(msg.symbolData()) != symbolLen {
		return fmt.Errorf("%w: expected %d got %d", ErrInvalidSymbolLen, symbolLen, len(msg.symbolData()))
	}
	if esi >= capacity {
		return fmt.Errorf("%w: esi %d cap %d", ErrInvalidSymbolID, esi, capacity)
	}
	if int(msg.appMessageLen) != appMessageLen {
		return fmt.Errorf("%w: expected %d got %d", ErrInvalidAppMsgLenInSymbol, appMessageLen, msg.appMessageLen)
	}
	if _, dup := seen[esi]; dup {
		return fmt.Errorf("%w: esi %d", ErrDuplicateSymbol, esi)
	}
	return nil
}

// decoderState — Rust DecoderState.
type decoderState struct {
	decoder       *raptor.ManagedDecoder
	appMessageLen int
	seenESIS      map[int]struct{}
	capacity      int
}

func newDecoderState(msg *validatedChunk) (*decoderState, error) {
	symbolLen := len(msg.symbolData())
	d, err := raptor.NewManagedDecoder(msg.numSourceSymbols, msg.encodedSymbolCapacity, symbolLen)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDecoderParams, err)
	}
	s := &decoderState{
		decoder:       d,
		appMessageLen: int(msg.appMessageLen),
		seenESIS:      make(map[int]struct{}),
		capacity:      msg.encodedSymbolCapacity,
	}
	if err := s.handleMessage(msg); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *decoderState) handleMessage(msg *validatedChunk) error {
	if err := validateSymbol(msg, s.decoder.SymbolLen(), s.appMessageLen, s.seenESIS, s.capacity); err != nil {
		return err
	}
	s.seenESIS[int(msg.chunkID)] = struct{}{}
	s.decoder.ReceivedEncodedSymbol(msg.symbolData(), int(msg.chunkID))
	return nil
}

// recentlyDecodedState — Rust RecentlyDecodedState.
type recentlyDecodedState struct {
	symbolLen     int
	appMessageLen int
	seenESIS      map[int]struct{}
	capacity      int
	tainted       bool
}

func (r *recentlyDecodedState) handleMessage(msg *validatedChunk) error {
	if r.tainted {
		return ErrMessageTainted
	}
	if err := validateSymbol(msg, r.symbolLen, r.appMessageLen, r.seenESIS, r.capacity); err != nil {
		return err
	}
	r.seenESIS[int(msg.chunkID)] = struct{}{}
	return nil
}

type tryDecodeStatus int

const (
	statusRejectedByCache tryDecodeStatus = iota
	statusNeedsMoreSymbols
	statusRecentlyDecoded
	statusDecoded
)

type decodedResult struct {
	status     tryDecodeStatus
	author     types.NodeId
	appMessage []byte
}

// decoderCache — Rust DecoderCache.
type decoderCache struct {
	recentlyDecoded *keyLRU // cacheKey → *recentlyDecodedState
	broadcast       *softQuotaCache
	validator       *softQuotaCache
	p2p             *softQuotaCache
}

func newDecoderCache(cfg decoderCacheConfig) *decoderCache {
	return &decoderCache{
		recentlyDecoded: newKeyLRU(cfg.recentlyDecodedCacheSize),
		broadcast:       newSoftQuotaCache(cfg.broadcastTier),
		validator:       newSoftQuotaCache(cfg.validatorTier),
		p2p:             newSoftQuotaCache(cfg.p2pTier),
	}
}

func (c *decoderCache) tierFor(msg *validatedChunk, vs *validator.ValidatorSet) *softQuotaCache {
	switch tierForMessage(msg, vs) {
	case tierBroadcast:
		return c.broadcast
	case tierValidator:
		return c.validator
	default:
		return c.p2p
	}
}

// tryDecode — Rust DecoderCache::try_decode.
func (c *decoderCache) tryDecode(msg *validatedChunk, validatorSet *validator.ValidatorSet, unixTsNow uint64) (decodedResult, error) {
	key := cacheKeyFromMessage(msg)

	if e := c.recentlyDecoded.get(key); e != nil {
		rd := e.(*recentlyDecodedState)
		if err := rd.handleMessage(msg); err != nil {
			return decodedResult{}, err
		}
		return decodedResult{status: statusRecentlyDecoded}, nil
	}

	tier := c.tierFor(msg, validatorSet)
	var state *decoderState
	if existing := tier.get(key); existing != nil {
		if err := existing.handleMessage(msg); err != nil {
			return decodedResult{}, err
		}
		state = existing
	} else {
		st, err := newDecoderState(msg)
		if err != nil {
			return decodedResult{}, err
		}
		tier.insert(key, msg, st, validatorSet, unixTsNow)
		// re-fetch: the just-inserted entry may have been evicted by
		// quota enforcement — Rust returns RejectedByCache then.
		state = tier.get(key)
		if state == nil {
			return decodedResult{status: statusRejectedByCache}, nil
		}
	}

	if !state.decoder.TryDecode() {
		return decodedResult{status: statusNeedsMoreSymbols}, nil
	}
	decoded := state.decoder.ReconstructSourceData()
	if decoded == nil {
		return decodedResult{}, ErrUnableToReconstruct
	}
	if len(decoded) > int(msg.appMessageLen) {
		decoded = decoded[:msg.appMessageLen]
	}
	tier.remove(key)
	c.recentlyDecoded.put(key, &recentlyDecodedState{
		symbolLen:     state.decoder.SymbolLen(),
		appMessageLen: state.appMessageLen,
		seenESIS:      state.seenESIS,
		capacity:      state.capacity,
	})
	return decodedResult{status: statusDecoded, author: msg.author, appMessage: decoded}, nil
}

// markTainted — Rust DecoderCache::mark_tainted.
func (c *decoderCache) markTainted(msg *validatedChunk) {
	key := cacheKeyFromMessage(msg)
	if e := c.recentlyDecoded.get(key); e != nil {
		e.(*recentlyDecodedState).tainted = true
	}
}

// --- soft quota cache ---

type quota struct {
	maxSlots int
	maxSize  int
}

type quotaEntryMeta struct {
	unixTs uint64
	size   int
}

type perAuthorIndex struct {
	quota quota
	size  int
	keys  map[cacheKey]quotaEntryMeta
}

func (a *perAuthorIndex) overquota() bool {
	return len(a.keys) > a.quota.maxSlots || a.size > a.quota.maxSize
}

// softQuotaCache — Rust SoftQuotaCache with the default FixedQuota policy.
type softQuotaCache struct {
	cfg           softQuotaConfig
	entries       *keyLRU // cacheKey → *quotaEntry
	perAuthor     map[types.NodeId]*perAuthorIndex
	totalSize     int
	maxTotalSize  int
	cooldownUntil time.Time
	pruneMinRatio float64
}

type quotaEntry struct {
	state  *decoderState
	author types.NodeId
	size   int
	unixTs uint64
}

func newSoftQuotaCache(cfg softQuotaConfig) *softQuotaCache {
	approxNumAuthors := cfg.totalSlots / cfg.minSlotsPerAuthor
	if approxNumAuthors < 1 {
		approxNumAuthors = 1
	}
	return &softQuotaCache{
		cfg:           cfg,
		entries:       newKeyLRU(0), // unbounded list; bounded via isFull
		perAuthor:     make(map[types.NodeId]*perAuthorIndex),
		maxTotalSize:  cfg.maxTotalSizePerAuthor * approxNumAuthors,
		pruneMinRatio: 0.1,
	}
}

func (c *softQuotaCache) calcQuota() quota {
	maxSlots := c.cfg.minSlotsPerAuthor
	if maxSlots > c.cfg.totalSlots {
		maxSlots = c.cfg.totalSlots
	}
	return quota{maxSlots: maxSlots, maxSize: c.cfg.maxTotalSizePerAuthor}
}

func (c *softQuotaCache) get(key cacheKey) *decoderState {
	e := c.entries.get(key)
	if e == nil {
		return nil
	}
	return e.(*quotaEntry).state
}

func (c *softQuotaCache) remove(key cacheKey) {
	v := c.entries.removeKey(key)
	if v == nil {
		return
	}
	e := v.(*quotaEntry)
	if ai := c.perAuthor[e.author]; ai != nil {
		if meta, ok := ai.keys[key]; ok {
			ai.size -= meta.size
			delete(ai.keys, key)
		}
		if len(ai.keys) == 0 {
			delete(c.perAuthor, e.author)
		}
	}
	c.totalSize -= e.size
}

func (c *softQuotaCache) isFull() bool {
	return c.entries.len() > c.cfg.totalSlots || c.totalSize > c.maxTotalSize
}

const pruneMaxTsDeltaMs = 10_000 // 10s — Rust PruneConfig::max_unix_ts_ms_delta

func (c *softQuotaCache) insert(key cacheKey, msg *validatedChunk, state *decoderState, _ *validator.ValidatorSet, now uint64) {
	q := c.calcQuota()
	size := int(msg.appMessageLen)
	ai := c.perAuthor[msg.author]
	if ai == nil {
		ai = &perAuthorIndex{quota: q, keys: make(map[cacheKey]quotaEntryMeta)}
		c.perAuthor[msg.author] = ai
	}
	ai.keys[key] = quotaEntryMeta{unixTs: msg.unixTsMs, size: size}
	ai.size += size
	c.totalSize += size
	c.entries.put(key, &quotaEntry{state: state, author: msg.author, size: size, unixTs: msg.unixTsMs})

	if !c.isFull() {
		return
	}

	if ai.overquota() {
		c.enforceQuota(msg.author, now)
		if !c.isFull() {
			return
		}
	}

	c.pruneExpiredAll(now)
	if !c.isFull() {
		return
	}

	// Upstream evicts a random entry when still full; the LRU tail is the
	// deterministic analogue (both are non-consensus bookkeeping choices).
	for c.isFull() {
		oldest := c.entries.oldest()
		if oldest == nil {
			return
		}
		c.remove(*oldest)
	}
}

// enforceQuota — Rust AuthorIndex::enforce_quota: expire old entries, then
// evict oldest until the author is within quota.
func (c *softQuotaCache) enforceQuota(author types.NodeId, now uint64) {
	ai := c.perAuthor[author]
	if ai == nil {
		return
	}
	if !ai.overquota() {
		return
	}
	if now > pruneMaxTsDeltaMs {
		threshold := now - pruneMaxTsDeltaMs
		for k, meta := range ai.keys {
			if meta.unixTs < threshold {
				c.remove(k)
			}
		}
	}
	for ai.overquota() {
		var oldestKey cacheKey
		var oldestTs uint64 = ^uint64(0)
		found := false
		for k, meta := range ai.keys {
			if meta.unixTs < oldestTs {
				oldestTs = meta.unixTs
				oldestKey = k
				found = true
			}
		}
		if !found {
			break
		}
		c.remove(oldestKey)
		ai = c.perAuthor[author]
		if ai == nil {
			break
		}
	}
}

// pruneExpiredAll — Rust AuthorIndex::prune_expired_all (with pruning
// cooldown).
func (c *softQuotaCache) pruneExpiredAll(now uint64) {
	if !c.cooldownUntil.IsZero() && time.Now().Before(c.cooldownUntil) {
		return
	}
	if now <= pruneMaxTsDeltaMs {
		return
	}
	threshold := now - pruneMaxTsDeltaMs
	var expired []cacheKey
	totalSlots := 0
	for _, ai := range c.perAuthor {
		totalSlots += len(ai.keys)
		for k, meta := range ai.keys {
			if meta.unixTs < threshold {
				expired = append(expired, k)
			}
		}
	}
	for _, k := range expired {
		c.remove(k)
	}
	if float64(len(expired)) < float64(totalSlots)*c.pruneMinRatio {
		c.cooldownUntil = time.Now().Add(10 * time.Second)
	}
}

// --- cacheKey LRU ---

type keyLRU struct {
	cap   int // 0 = unbounded
	ll    *list.List
	items map[cacheKey]*list.Element
}

type lruPair struct {
	key cacheKey
	val any
}

func newKeyLRU(capacity int) *keyLRU {
	return &keyLRU{cap: capacity, ll: list.New(), items: make(map[cacheKey]*list.Element)}
}

func (l *keyLRU) get(key cacheKey) any {
	e, ok := l.items[key]
	if !ok {
		return nil
	}
	l.ll.MoveToFront(e)
	return e.Value.(lruPair).val
}

func (l *keyLRU) put(key cacheKey, val any) {
	if e, ok := l.items[key]; ok {
		l.ll.MoveToFront(e)
		e.Value = lruPair{key, val}
		return
	}
	l.items[key] = l.ll.PushFront(lruPair{key, val})
	if l.cap > 0 && l.ll.Len() > l.cap {
		l.removeOldest()
	}
}

func (l *keyLRU) removeKey(key cacheKey) any {
	e, ok := l.items[key]
	if !ok {
		return nil
	}
	l.ll.Remove(e)
	delete(l.items, key)
	return e.Value.(lruPair).val
}

func (l *keyLRU) oldest() *cacheKey {
	e := l.ll.Back()
	if e == nil {
		return nil
	}
	k := e.Value.(lruPair).key
	return &k
}

func (l *keyLRU) removeOldest() {
	e := l.ll.Back()
	if e == nil {
		return
	}
	delete(l.items, e.Value.(lruPair).key)
	l.ll.Remove(e)
}

func (l *keyLRU) len() int { return l.ll.Len() }
