// Package metrics ports monad-consensus-types::metrics — the counters and
// gauges consensus writes to. Backed by plain integers so the core has no
// metrics-backend dependency; an exporter can snapshot/copy these.
package metrics

// Counter — monotonically increasing event count.
type Counter uint64

func (c *Counter) Inc()         { *c++ }
func (c *Counter) Add(v uint64) { *c += Counter(v) }
func (c *Counter) Get() uint64  { return uint64(*c) }

// Gauge — settable value (used for percentile metrics).
type Gauge uint64

func (g *Gauge) Set(v uint64) { *g = Gauge(v) }
func (g *Gauge) Get() uint64  { return uint64(*g) }

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
}

// VoteDelay — Rust vote-delay percentile gauges.
type VoteDelay struct {
	ReadyAfterTimerStartP50Ms Gauge
	ReadyAfterTimerStartP90Ms Gauge
	ReadyAfterTimerStartP99Ms Gauge
}

// Metrics — Rust metrics::Metrics.
type Metrics struct {
	ConsensusEvents ConsensusEvents
	VoteDelay       VoteDelay
}
