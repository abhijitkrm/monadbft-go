// Package metrics ports monad-consensus-types::metrics — the counters and
// gauges consensus writes to. Atomics so a Prometheus exporter can scrape
// off the node loop without racing consensus.
package metrics

import "sync/atomic"

// Counter — monotonically increasing event count. Atomic so an exporter
// can scrape off the node loop.
type Counter struct{ v atomic.Uint64 }

func (c *Counter) Inc()         { c.v.Add(1) }
func (c *Counter) Add(v uint64) { c.v.Add(v) }
func (c *Counter) Get() uint64  { return c.v.Load() }

// Gauge — settable value (used for percentile metrics).
type Gauge struct{ v atomic.Uint64 }

func (g *Gauge) Set(v uint64) { g.v.Store(v) }
func (g *Gauge) Get() uint64  { return g.v.Load() }

// ConsensusEvents — Rust metrics::ConsensusEvents (the subset used by
// consensus-state).
type ConsensusEvents struct {
	LocalTimeout                 Counter
	OldVoteReceived              Counter
	FutureVoteReceived           Counter
	VoteReceived                 Counter
	CreatedQC                    Counter
	OldRemoteTimeout             Counter
	RemoteTimeoutMsg             Counter
	RemoteTimeoutMsgWithTC       Counter
	RemoteTimeoutMsgWithFutureTC Counter
	HandleRoundRecovery          Counter
	InvalidRoundRecoveryLeader   Counter
	OldNoEndorsementReceived     Counter
	FutureNoEndorsementReceived  Counter
	HandleNoEndorsement          Counter
	CreatedNEC                   Counter
	HandleAdvanceRound           Counter
	ProcessOldQC                 Counter
	ProcessQC                    Counter
	ProcessOldTC                 Counter
	ProcessTC                    Counter
	CommitBlock                  Counter
	FailedTSValidation           Counter
	CreatedVote                  Counter
	RxExecutionLagging           Counter
	HandleProposal               Counter
	InvalidProposalRoundLeader   Counter
	OutOfOrderProposals          Counter
	ProposalWithTC               Counter
	TriggerStateSync             Counter
	CreatingProposal             Counter
}

// VoteDelay — Rust vote-delay percentile gauges.
type VoteDelay struct {
	ReadyAfterTimerStartP50Ms Gauge
	ReadyAfterTimerStartP90Ms Gauge
	ReadyAfterTimerStartP99Ms Gauge
}

// ValidationErrors — Rust metrics::ValidationErrors.
type ValidationErrors struct {
	InvalidAuthor           Counter
	NotWellFormedSig        Counter
	InvalidSignature        Counter
	InvalidTcRound          Counter
	DuplicateTcTipRound     Counter
	EmptySignersTcTipRound  Counter
	TooManyTcTipRound       Counter
	InsufficientStake       Counter
	ValDataUnavailable      Counter
	SignaturesDuplicateNode Counter
	InvalidVoteMessage      Counter
	InvalidVersion          Counter
	InvalidEpoch            Counter
}

// BlocksyncEvents — Rust metrics::BlocksyncEvents.
type BlocksyncEvents struct {
	PeerHeadersRequest           Counter
	PeerHeadersRequestSuccessful Counter
	PeerHeadersRequestFailed     Counter
	PeerPayloadRequest           Counter
	PeerPayloadRequestSuccessful Counter
	PeerPayloadRequestFailed     Counter

	SelfHeadersRequest            Counter
	SelfHeadersResponseSuccessful Counter
	SelfHeadersResponseFailed     Counter
	SelfPayloadRequest            Counter
	SelfPayloadResponseSuccessful Counter
	SelfPayloadResponseFailed     Counter
	SelfPayloadRequestsInFlight   Gauge

	HeadersResponseSuccessful Counter
	HeadersResponseFailed     Counter
	HeadersResponseUnexpected Counter
	HeadersValidationFailed   Counter
	PayloadResponseSuccessful Counter
	PayloadResponseFailed     Counter
	PayloadResponseUnexpected Counter
	NumHeadersReceived        Counter
	RequestTimeout            Counter
	RequestFailedNoPeers      Counter
}

// NodeState — Rust metrics::NodeState.
type NodeState struct {
	SelfStakeBps Gauge
}

// Metrics — Rust metrics::Metrics.
type Metrics struct {
	ConsensusEvents  ConsensusEvents
	ValidationErrors ValidationErrors
	BlocksyncEvents  BlocksyncEvents
	NodeState        NodeState
	VoteDelay        VoteDelay
}
