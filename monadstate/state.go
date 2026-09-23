// Package monadstate ports monad-state: the top-level MonadState dispatcher
// that owns the ConsensusMode (Sync/Live), routes MonadEvents to child
// states, and translates their commands into executor-facing glue.Commands.
package monadstate

import (
	"math/big"

	"github.com/abhijitkrm/monadbft-go/blocksync"
	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/metrics"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validation"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// Role — Rust monad-state::Role.
type Role int

const (
	RoleFullNode Role = iota
	RoleValidator
)

// consensusMode — Rust ConsensusMode: Sync (block-buffer + db statesync) or
// Live (a running ConsensusState).
type consensusMode struct {
	live *consensusstate.State

	// Sync-mode fields (live == nil)
	highCertificate       cstypes.RoundCertificate
	blockBuffer           *BlockBuffer
	dbStatus              DbSyncStatus
	updatingTarget        bool
	lockedEpochValidators []glue.ValidatorSetDataWithEpoch
}

func (m *consensusMode) isLive() bool { return m.live != nil }

func (m *consensusMode) currentEpoch() types.Epoch {
	if m.isLive() {
		return m.live.Consensus.GetCurrentEpoch()
	}
	hc := m.highCertificate
	if hc.IsQC {
		return hc.QC.Info.Epoch
	}
	return hc.TC.Epoch
}

func (m *consensusMode) currentRound() types.Round {
	if m.isLive() {
		return m.live.Consensus.GetCurrentRound()
	}
	return m.highCertificate.Round() + 1
}

// MonadState — Rust MonadState: the top-level event dispatcher.
type MonadState struct {
	keypair     *crypto.SecpKeyPair
	certKeypair *crypto.BlsKeyPair
	nodeid      types.NodeId

	consensusConfig *consensusstate.Config

	consensus        consensusMode
	certificateCache *validation.CertificateCache
	blockSync        *blocksync.BlockSync

	leaderElection validator.LeaderElection
	epochManager   *validator.EpochManager
	valEpochMap    *validator.ValidatorsEpochMapping

	// Excludes self; expiry nodeid -> round
	secondaryRaptorcastPeers map[types.NodeId]types.Round

	blockTimestamp *consensusstate.BlockTimestamp
	blockValidator blocktree.BlockValidator
	blockPolicy    blocktree.BlockPolicy
	stateRead      blocktree.ExecutionStateRead
	beneficiary    [20]byte

	metrics *metrics.Metrics

	version glue.MonadVersion

	whitelistedStatesyncNodes map[types.NodeId]struct{}
	statesyncExpandToGroup    bool
	serveStatesync            bool
}

// Builder — Rust MonadStateBuilder.
type Builder struct {
	LeaderElection validator.LeaderElection
	BlockValidator blocktree.BlockValidator
	BlockPolicy    blocktree.BlockPolicy
	StateRead      blocktree.ExecutionStateRead
	Forkpoint      Forkpoint

	LockedEpochValidators []glue.ValidatorSetDataWithEpoch

	Keypair     *crypto.SecpKeyPair
	CertKeypair *crypto.BlsKeyPair
	Beneficiary [20]byte

	BlockSyncOverridePeers []types.NodeId
	BlocksyncRngSeed       *uint64

	WhitelistedStatesyncNodes map[types.NodeId]struct{}
	StatesyncExpandToGroup    bool
	ServeStatesync            bool

	ConsensusConfig *consensusstate.Config
}

// Build — Rust MonadStateBuilder::build.
func (b Builder) Build() (*MonadState, []glue.Command) {
	if err := b.Forkpoint.Validate(b.LockedEpochValidators, b.LeaderElection); err != nil {
		panic("monadstate: invalid forkpoint: " + err.Error())
	}

	cc := b.ConsensusConfig
	epochManager := validator.NewEpochManager(
		cc.ChainConfig.GetEpochLength(),
		cc.ChainConfig.GetEpochStartDelay(),
		b.Forkpoint.GetEpochStarts(),
	)

	nodeid := types.NewNodeId(b.Keypair.PubKey())
	blockTimestamp := consensusstate.NewBlockTimestamp(
		types.U128FromUint64(uint64(5*cc.Delta.Nanoseconds())),
		cc.TimestampLatencyEstimateNs,
	)

	ms := &MonadState{
		keypair:     b.Keypair,
		certKeypair: b.CertKeypair,
		nodeid:      nodeid,

		consensusConfig: cc,

		consensus: consensusMode{
			live:                  nil,
			highCertificate:       b.Forkpoint.Checkpoint.HighCertificate,
			blockBuffer:           NewBlockBuffer(cc.ExecutionDelay, b.Forkpoint.Checkpoint.Root, cc.StatesyncToLiveThreshold),
			dbStatus:              DbSyncWaiting,
			lockedEpochValidators: append([]glue.ValidatorSetDataWithEpoch(nil), b.LockedEpochValidators...),
		},
		certificateCache: validation.NewCertificateCache(),
		blockSync:        blocksync.New(b.BlockSyncOverridePeers, nodeid, b.BlocksyncRngSeed),

		leaderElection: b.LeaderElection,
		epochManager:   epochManager,
		valEpochMap:    validator.NewValidatorsEpochMapping(),

		secondaryRaptorcastPeers: make(map[types.NodeId]types.Round),

		blockTimestamp: blockTimestamp,
		blockValidator: b.BlockValidator,
		blockPolicy:    b.BlockPolicy,
		stateRead:      b.StateRead,
		beneficiary:    b.Beneficiary,

		metrics: &metrics.Metrics{},
		version: glue.Version(),

		whitelistedStatesyncNodes: b.WhitelistedStatesyncNodes,
		statesyncExpandToGroup:    b.StatesyncExpandToGroup,
		serveStatesync:            b.ServeStatesync,
	}
	if ms.whitelistedStatesyncNodes == nil {
		ms.whitelistedStatesyncNodes = make(map[types.NodeId]struct{})
	}

	var initCmds []glue.Command
	for _, vset := range b.LockedEpochValidators {
		initCmds = append(initCmds, ms.Update(glue.EvUpdateValidators{ValidatorSetDataWithEpoch: vset})...)
	}
	initCmds = append(initCmds, ms.maybeStartConsensus()...)
	return ms, initCmds
}

// Consensus — Rust MonadState::consensus (Some iff Live).
func (m *MonadState) Consensus() *consensusstate.State { return m.consensus.live }

// IsStatesyncing — Rust is_statesyncing.
func (m *MonadState) IsStatesyncing() bool { return m.consensus.live == nil }

// Metrics — Rust metrics().
func (m *MonadState) Metrics() *metrics.Metrics { return m.metrics }

// EpochManager — Rust epoch_manager().
func (m *MonadState) EpochManager() *validator.EpochManager { return m.epochManager }

// ValidatorsEpochMapping — Rust validators_epoch_mapping().
func (m *MonadState) ValidatorsEpochMapping() *validator.ValidatorsEpochMapping {
	return m.valEpochMap
}

// NodeID — Rust nodeid.
func (m *MonadState) NodeID() types.NodeId { return m.nodeid }

// GetRole — Rust get_role: FullNode while syncing or when not in the current
// validator set; Validator otherwise.
func (m *MonadState) GetRole() Role {
	if !m.consensus.isLive() {
		return RoleFullNode
	}
	epoch := m.consensus.currentEpoch()
	vs, ok := m.valEpochMap.GetValSet(epoch)
	if !ok {
		panic("monadstate: unknown validator set for current epoch")
	}
	if vs.IsMember(m.nodeid) {
		return RoleValidator
	}
	return RoleFullNode
}

// getSelfStakeBps — Rust get_self_stake_bps.
func (m *MonadState) getSelfStakeBps() uint64 {
	if m.IsStatesyncing() {
		return 0
	}
	epoch := m.consensus.currentEpoch()
	vs, ok := m.valEpochMap.GetValSet(epoch)
	if !ok {
		panic("monadstate: current validator set is populated")
	}
	selfStake, ok := vs.StakeOf(m.nodeid)
	if !ok {
		return 0
	}
	total := vs.TotalStake()
	// bps = ceil(self_stake * 10_000 / total)
	n := selfStake.Big()
	n.Mul(n, big.NewInt(10_000))
	t := total.Big()
	n.Add(n, t)
	n.Sub(n, big.NewInt(1))
	n.Div(n, t)
	return n.Uint64()
}

// shouldServiceStatesyncRequest — Rust should_service_statesync_request.
func (m *MonadState) shouldServiceStatesyncRequest(sender types.NodeId, _ *glue.StateSyncRequest) bool {
	if !m.serveStatesync {
		return false
	}
	if m.GetRole() == RoleFullNode {
		return true
	}
	epoch := m.consensus.currentEpoch()
	if vs, ok := m.valEpochMap.GetValSet(epoch); ok && vs.IsMember(sender) {
		return true
	}
	_, ok := m.whitelistedStatesyncNodes[sender]
	return ok
}

// Update — Rust MonadState::update: the top-level event dispatch.
func (m *MonadState) Update(event glue.MonadEvent) []glue.Command {
	switch ev := event.(type) {

	case glue.ConsensusEvent:
		consensusCmds := m.updateConsensus(ev)

		takeCheckpoint := false
		for _, wc := range consensusCmds {
			switch wc.command.(type) {
			case consensusstate.CmdEnterRound:
				takeCheckpoint = true
			case consensusstate.CmdCommitBlocks:
				if wc.command.(consensusstate.CmdCommitBlocks).Commit.Kind == consensusstate.CommitFinalized {
					takeCheckpoint = true
				}
			}
		}
		for _, wc := range consensusCmds {
			if _, ok := wc.command.(consensusstate.CmdEnterRound); ok {
				m.metrics.NodeState.SelfStakeBps.Set(m.getSelfStakeBps())
				break
			}
		}

		var cmds []glue.Command
		for _, wc := range consensusCmds {
			cmds = append(cmds, m.fromConsensusCommand(wc)...)
		}
		if takeCheckpoint {
			if cp := m.checkpoint(); cp != nil {
				cmds = append(cmds, cp)
			}
		}
		return cmds

	case glue.BlockSyncEvent:
		blockSyncCmds := m.updateBlockSync(ev)
		var cmds []glue.Command
		for _, wc := range blockSyncCmds {
			cmds = append(cmds, m.fromBlockSyncCommand(wc)...)
		}
		return cmds

	case glue.EvUpdateValidators:
		vsetData := ev.ValidatorSetDataWithEpoch
		var valIDs []types.NodeId
		for _, vd := range vsetData.Validators.Validators {
			valIDs = append(valIDs, vd.NodeId)
		}

		var valData []validator.ValidatorData
		var mapEntries []struct {
			NodeId     types.NodeId
			CertPubKey crypto.BlsPubKey
		}
		for _, vd := range vsetData.Validators.Validators {
			pk, err := crypto.BlsPubKeyUncompress(vd.CertPubKey[:])
			if err != nil {
				panic("monadstate: invalid cert pubkey in validator set update")
			}
			valData = append(valData, validator.ValidatorData{
				NodeId: vd.NodeId, Stake: vd.Stake, CertPubKey: pk,
			})
			mapEntries = append(mapEntries, struct {
				NodeId     types.NodeId
				CertPubKey crypto.BlsPubKey
			}{vd.NodeId, pk})
		}
		m.valEpochMap.Insert(vsetData.Epoch, valData, validator.NewValidatorMapping(mapEntries))

		var cmds []glue.Command
		if epochStart, ok := m.epochManager.GetEpochStart(vsetData.Epoch); ok {
			cmds = append(cmds, glue.RouterAddEpochValidatorSet{
				Epoch:        vsetData.Epoch,
				EpochStart:   epochStart,
				ValidatorSet: vsetData.Validators.GetStakes(),
			})
		}
		cmds = append(cmds, glue.ConfigFileValidatorSetData{ValidatorSetData: vsetData})

		if m.statesyncExpandToGroup && m.IsStatesyncing() && containsNode(valIDs, m.nodeid) {
			var excl []types.NodeId
			for _, p := range valIDs {
				if p != m.nodeid {
					excl = append(excl, p)
				}
			}
			cmds = append(cmds, glue.StateSyncExpandUpstreamPeers{Peers: excl})
		}
		return cmds

	case glue.MempoolEvent:
		return m.handleMempoolEvent(ev)

	case glue.StateSyncEvent:
		return m.updateStateSync(ev)

	case glue.ControlPanelEvent:
		return m.updateControlPanel(ev)

	case glue.EvTimestampUpdate:
		m.blockTimestamp.UpdateTime(ev.Timestamp)
		if m.consensus.isLive() {
			m.consensus.live.Consensus.RefreshVoteDelayMetrics(ev.Timestamp, m.metrics)
		}
		return nil

	case glue.ConfigEvent:
		return m.updateConfig(ev)

	case glue.EvSecondaryRaptorcastPeersUpdate:
		var excl []types.NodeId
		for _, p := range ev.ConfirmGroupPeers {
			if p != m.nodeid {
				excl = append(excl, p)
			}
		}
		currentRound := m.consensus.currentRound()
		for id, exp := range m.secondaryRaptorcastPeers {
			if exp <= currentRound {
				delete(m.secondaryRaptorcastPeers, id)
			}
		}
		for _, p := range excl {
			if old, ok := m.secondaryRaptorcastPeers[p]; ok && old > ev.ExpiryRound {
				continue
			}
			m.secondaryRaptorcastPeers[p] = ev.ExpiryRound
		}
		var cmds []glue.Command
		if m.statesyncExpandToGroup && m.IsStatesyncing() {
			cmds = append(cmds, glue.StateSyncExpandUpstreamPeers{Peers: excl})
		}
		return cmds
	}
	return nil
}

// updateStateSync — Rust MonadEvent::StateSyncEvent arm.
func (m *MonadState) updateStateSync(ev glue.StateSyncEvent) []glue.Command {
	switch e := ev.(type) {
	case glue.EvStateSyncInbound:
		if e.Message.Kind == glue.SSNRequest {
			if !m.shouldServiceStatesyncRequest(e.From, &e.Message.Request) {
				return []glue.Command{glue.RouterPublish{
					Target: types.RouterTarget{Kind: types.RouterTcpPointToPoint, To: e.From},
					Message: &glue.VerifiedMonadMessage{
						Kind:             5,
						StateSyncMessage: &glue.StateSyncNetworkMessage{Kind: glue.SSNNotWhitelisted},
					},
				}}
			}
		}
		return []glue.Command{glue.StateSyncMessage{To: e.From, Message: e.Message}}

	case glue.EvStateSyncOutbound:
		return []glue.Command{glue.RouterPublish{
			Target:  types.RouterTarget{Kind: types.RouterTcpPointToPoint, To: e.To},
			Message: &glue.VerifiedMonadMessage{Kind: 5, StateSyncMessage: &e.Message},
		}}

	case glue.EvStateSyncRequestSync:
		if m.consensus.isLive() {
			panic("monadstate: Live -> RequestSync is an invalid state transition")
		}
		m.consensus.highCertificate = cstypes.RoundCertificate{IsQC: true, QC: &e.HighQC}
		m.consensus.blockBuffer.ReRoot(e.Root)
		m.consensus.dbStatus = DbSyncWaiting
		m.consensus.updatingTarget = false
		return m.maybeStartConsensus()

	case glue.EvStateSyncDoneSync:
		if m.consensus.isLive() {
			panic("monadstate: DoneSync invoked while ConsensusState is live")
		}
		if m.consensus.dbStatus != DbSyncWaiting && m.consensus.dbStatus != DbSyncStarted {
			panic("monadstate: unexpected db_status on DoneSync")
		}
		delay := m.consensusConfig.ExecutionDelay
		var maybeTarget *types.SeqNum
		if rs, ok := m.consensus.blockBuffer.RootSeqNum(); ok {
			t := rs
			if t >= delay {
				t -= delay
			} else {
				t = 0
			}
			maybeTarget = &t
		}
		if maybeTarget != nil && e.SeqNum >= *maybeTarget {
			if e.SeqNum != *maybeTarget {
				panic("monadstate: DoneSync seq_num != target")
			}
			if m.consensus.dbStatus != DbSyncStarted {
				panic("monadstate: DoneSync before Started")
			}
			m.consensus.dbStatus = DbSyncDone
			return m.maybeStartConsensus()
		}
		return nil

	case glue.EvStateSyncBlockSync:
		if m.consensus.isLive() {
			return nil
		}
		for _, fb := range e.FullBlocks {
			m.consensus.blockBuffer.HandleBlocksync(fb)
		}
		return m.maybeStartConsensus()
	}
	return nil
}

// updateControlPanel — Rust MonadEvent::ControlPanelEvent arm.
func (m *MonadState) updateControlPanel(ev glue.ControlPanelEvent) []glue.Command {
	switch e := ev.(type) {
	case glue.EvGetMetrics:
		return []glue.Command{glue.ControlPanelRead{Cmd: glue.ReadCommand{Kind: glue.ReadGetMetrics}}}
	case glue.EvClearMetrics:
		return []glue.Command{glue.ControlPanelRead{Cmd: glue.ReadCommand{Kind: glue.ReadClearMetrics}}}
	case glue.EvUpdateLogFilter:
		return []glue.Command{glue.ControlPanelWrite{Cmd: glue.WriteCommand{Kind: glue.WriteUpdateLogFilter, UpdateLogFilter: e.Filter}}}
	case glue.EvGetPeers:
		if e.Peers.Request {
			return []glue.Command{glue.RouterGetPeers{}}
		}
		return []glue.Command{glue.ControlPanelRead{Cmd: glue.ReadCommand{Kind: glue.ReadGetPeers, GetPeers: &e.Peers}}}
	case glue.EvGetFullNodes:
		if e.FullNodes.Request {
			return []glue.Command{glue.RouterGetFullNodes{}}
		}
		return []glue.Command{glue.ControlPanelRead{Cmd: glue.ReadCommand{Kind: glue.ReadGetFullNodes, FullNodes: &e.FullNodes}}}
	case glue.EvReloadConfig:
		if e.Request {
			return []glue.Command{glue.ConfigReloadReload{}}
		}
		return []glue.Command{glue.ControlPanelWrite{Cmd: glue.WriteCommand{Kind: glue.WriteReloadConfig, ReloadConfig: true}}}
	}
	return nil
}

// updateConfig — Rust MonadEvent::ConfigEvent arm.
func (m *MonadState) updateConfig(ev glue.ConfigEvent) []glue.Command {
	switch e := ev.(type) {
	case glue.EvConfigUpdate:
		m.blockSync.SetOverridePeers(e.Update.BlocksyncOverridePeers)
		m.whitelistedStatesyncNodes = make(map[types.NodeId]struct{})
		for _, n := range e.Update.DedicatedFullNodes {
			m.whitelistedStatesyncNodes[n] = struct{}{}
		}
		for _, n := range e.Update.PrioritizedFullNodes {
			m.whitelistedStatesyncNodes[n] = struct{}{}
		}
		return []glue.Command{
			glue.RouterUpdateFullNodes{
				DedicatedFullNodes:   e.Update.DedicatedFullNodes,
				PrioritizedFullNodes: e.Update.PrioritizedFullNodes,
			},
			glue.ControlPanelWrite{Cmd: glue.WriteCommand{Kind: glue.WriteReloadConfig, ReloadConfig: true}},
		}
	case glue.EvConfigLoadError:
		return []glue.Command{glue.ControlPanelWrite{Cmd: glue.WriteCommand{Kind: glue.WriteReloadConfig, ReloadConfig: true}}}
	case glue.EvKnownPeersUpdate:
		return []glue.Command{glue.RouterUpdatePeers{
			PeerEntries:          e.Update.KnownPeers,
			DedicatedFullNodes:   e.Update.DedicatedFullNodes,
			PrioritizedFullNodes: e.Update.PrioritizedFullNodes,
		}}
	}
	return nil
}

// maybeStartConsensus — Rust maybe_start_consensus: transition Sync -> Live
// once the block buffer is populated and the DB has caught up.
func (m *MonadState) maybeStartConsensus() []glue.Command {
	if m.consensus.isLive() {
		panic("monadstate: maybe_start_consensus invoked while live")
	}
	bb := m.consensus.blockBuffer
	rootParentChain := bb.RootParentChain()

	if blockRange := bb.NeedsBlocksync(); blockRange != nil {
		return m.Update(glue.EvBlockSyncSelfRequest{
			Requester:  blocksync.SelfRequesterStateSync,
			BlockRange: *blockRange,
		})
	}

	rootInfo := bb.RootInfo()
	if rootInfo == nil {
		panic("monadstate: blocksync done, root block should be known")
	}
	rootSeqNum := rootInfo.SeqNum

	delay := m.consensusConfig.ExecutionDelay
	delaySeqNum := rootSeqNum
	if delaySeqNum >= delay {
		delaySeqNum -= delay
	} else {
		delaySeqNum = 0
	}

	if m.consensus.dbStatus == DbSyncWaiting {
		m.consensus.dbStatus = DbSyncStarted

		// the block at delaySeqNum: its id is the parent of the (delay+1) block.
		delayChildSeqNum := delaySeqNum + 1
		var delayBlockId types.BlockId
		found := false
		for _, blk := range rootParentChain {
			if blk.GetSeqNum() == delayChildSeqNum {
				delayBlockId = blk.GetParentId()
				found = true
				break
			}
		}
		if !found {
			if rootSeqNum != types.GENESIS_SEQ_NUM {
				panic("monadstate: root parent chain missing delay blocks")
			}
			delayBlockId = types.GENESIS_BLOCK_ID
		}

		if _, err := m.stateRead.GetExecutionResult(delayBlockId, delaySeqNum, true); err == nil {
			return m.Update(glue.EvStateSyncDoneSync{SeqNum: delaySeqNum})
		}

		delayed := bb.RootDelayedExecutionResult()
		if len(delayed) != 1 {
			panic("monadstate: is DB state empty? expected 1 delayed execution result")
		}
		m.metrics.ConsensusEvents.TriggerStateSync.Inc()
		return []glue.Command{glue.StateSyncRequestSync{Header: delayed[0]}}
	}
	if m.consensus.dbStatus == DbSyncStarted {
		return nil
	}

	// dbStatus == Done: bring the node live.
	var cmds []glue.Command

	// the last 2*delay committed blocks (oldest-first), policy-validated.
	var lastCommitted []*cstypes.ConsensusFullBlock
	n := int(delay) * 2
	for i, blk := range rootParentChain {
		if i >= n {
			break
		}
		validated, err := m.blockValidator.Validate(
			blk.Header, blk.Body, nil, m.consensusConfig.ChainConfig, m.metrics)
		if err != nil {
			panic("monadstate: majority committed invalid block")
		}
		_ = validated
		lastCommitted = append(lastCommitted, blk)
	}
	// reverse to oldest-first
	for i, j := 0, len(lastCommitted)-1; i < j; i, j = i+1, j-1 {
		lastCommitted[i], lastCommitted[j] = lastCommitted[j], lastCommitted[i]
	}

	m.blockPolicy.Reset(lastCommitted)
	cmds = append(cmds, glue.TxPoolReset{LastDelayCommittedBlocks: lastCommitted})

	for _, blk := range lastCommitted {
		m.epochManager.ScheduleEpochStart(blk.GetSeqNum(), blk.GetBlockRound())
		cmds = append(cmds,
			glue.LedgerCommit{Commit: glue.OptimisticCommit{Kind: glue.CommitProposed, Block: blk, IsCanonical: true}},
			glue.LedgerCommit{Commit: glue.OptimisticCommit{Kind: glue.CommitFinalized, Block: blk}},
			glue.ValSetNotifyFinalized{SeqNum: blk.GetSeqNum()},
		)
	}

	// assert locked-epoch validator sets match execution state.
	for _, ev := range m.consensus.lockedEpochValidators {
		lockedEpoch := ev.Epoch
		if lockedEpoch >= m.consensusConfig.ChainConfig.GetStakingActivation() {
			expected := make(map[[33]byte]struct {
				stake types.Stake
				cert  [48]byte
			})
			for _, vd := range ev.Validators.Validators {
				expected[[33]byte(vd.NodeId.PubKey)] = struct {
					stake types.Stake
					cert  [48]byte
				}{vd.Stake, vd.CertPubKey}
			}
			dbData := m.stateRead.ReadValsetAtBlock(delaySeqNum, lockedEpoch)
			if len(dbData) != len(expected) {
				panic("monadstate: unexpected locked epoch valset")
			}
			for _, d := range dbData {
				exp, ok := expected[d.PubKey]
				if !ok || exp.stake.Cmp(d.Stake) != 0 || exp.cert != d.CertPubKey {
					panic("monadstate: unexpected locked epoch valset")
				}
			}
		}
	}

	cachedProposals := bb.Proposals()

	live := consensusstate.NewConsensusState(m.epochManager, m.consensusConfig, *rootInfo, m.consensus.highCertificate)
	// bind the shared environment into the wrapper
	liveState := &consensusstate.State{
		Consensus:      live,
		Metrics:        m.metrics,
		EpochManager:   m.epochManager,
		BlockPolicy:    m.blockPolicy,
		StateRead:      m.stateRead,
		ValEpochMap:    m.valEpochMap,
		Election:       m.leaderElection,
		Version:        m.version.ProtocolVersion,
		BlockTimestamp: m.blockTimestamp,
		BlockValidator: m.blockValidator,
		Beneficiary:    m.beneficiary,
		NodeId:         m.nodeid,
		Config:         m.consensusConfig,
		Keypair:        m.keypair,
		CertKeypair:    m.certKeypair,
	}
	currentRound := live.GetCurrentRound()
	currentEpoch := live.GetCurrentEpoch()
	m.consensus.live = liveState

	// Pacemaker only emits EnterRound on a strictly-higher certificate; seed the
	// router/peer-discovery with the bootstrap round here.
	cmds = append(cmds, glue.RouterUpdateCurrentRound{Epoch: currentEpoch, Round: currentRound})
	cmds = append(cmds, glue.StateSyncStartExecution{})

	cmds = append(cmds, m.Update(glue.EvConsensusSendVote{Round: currentRound})...)
	cmds = append(cmds, m.Update(glue.EvConsensusTimeout{Round: currentRound})...)

	for _, bp := range cachedProposals {
		cmds = append(cmds, m.handleValidatedProposal(bp.author, bp.proposal)...)
	}

	// initiate blocksyncing from high_qc if no cached proposals advanced it
	blocksyncCmds := live.RequestBlocksIfMissingAncestor()
	for _, c := range blocksyncCmds {
		cmds = append(cmds, m.fromConsensusCommand(wrappedConsensusCommand{
			upcomingLeaderRounds: liveState.IterUpcomingSelfLeaderRounds(),
			command:              c,
		})...)
	}
	return cmds
}

func containsNode(ids []types.NodeId, id types.NodeId) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
