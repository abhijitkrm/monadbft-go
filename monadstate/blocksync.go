package monadstate

import (
	"time"

	"github.com/abhijitkrm/monadbft-go/blocksync"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
)

// wrappedBlockSyncCommand — Rust WrappedBlockSyncCommand: a BlockSyncCommand
// plus the request timeout (delta*7) attached at wrap time.
type wrappedBlockSyncCommand struct {
	requestTimeout time.Duration
	command        blocksync.Command
}

// updateBlockSync — Rust BlockSyncChildState::update.
func (m *MonadState) updateBlockSync(ev glue.BlockSyncEvent) []wrappedBlockSyncCommand {
	var cache blocksync.Cache
	if m.consensus.isLive() {
		cache.BlockTree = m.consensus.live.Consensus.PendingBlockTree
	} else {
		cache.PayloadCache = m.consensus.blockBuffer.PayloadCache()
	}

	w := &blocksync.Wrapper{
		BS:                       m.blockSync,
		Cache:                    cache,
		Metrics:                  m.metrics,
		NodeID:                   m.nodeid,
		CurrentEpoch:             m.consensus.currentEpoch(),
		EpochManager:             m.epochManager,
		ValEpochMap:              m.valEpochMap,
		SecondaryRaptorcastPeers: m.secondaryRaptorcastPeers,
	}

	var cmds []blocksync.Command
	switch e := ev.(type) {
	case glue.EvBlockSyncRequest:
		cmds = w.HandlePeerRequest(e.Sender, e.Request)
	case glue.EvBlockSyncSelfRequest:
		cmds = w.HandleSelfRequest(e.Requester, e.BlockRange)
	case glue.EvBlockSyncSelfCancelRequest:
		w.HandleSelfCancelRequest(e.Requester, e.BlockRange)
	case glue.EvBlockSyncSelfResponse:
		cmds = w.HandleLedgerResponse(e.Response)
	case glue.EvBlockSyncResponse:
		cmds = w.HandlePeerResponse(e.Sender, e.Response)
	case glue.EvBlockSyncTimeout:
		cmds = w.HandleTimeout(e.Request)
	}

	timeout := m.consensusConfig.Delta * 7
	out := make([]wrappedBlockSyncCommand, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, wrappedBlockSyncCommand{requestTimeout: timeout, command: c})
	}
	return out
}

// fromBlockSyncCommand — Rust From<WrappedBlockSyncCommand> for Vec<Command>.
func (m *MonadState) fromBlockSyncCommand(w wrappedBlockSyncCommand) []glue.Command {
	switch c := w.command.(type) {
	case *blocksync.CmdSendRequest:
		return []glue.Command{glue.RouterPublish{
			Target:  types.RouterTarget{Kind: types.RouterTcpPointToPoint, To: c.To},
			Message: &glue.VerifiedMonadMessage{Kind: 2, BlockSyncRequest: &c.Request},
		}}
	case *blocksync.CmdScheduleTimeout:
		return []glue.Command{glue.TimerSchedule{
			Duration:  w.requestTimeout,
			Variant:   glue.TimeoutVariantBlockSync(c.Request),
			OnTimeout: glue.EvBlockSyncTimeout{Request: c.Request},
		}}
	case *blocksync.CmdResetTimeout:
		return []glue.Command{glue.TimerScheduleReset{Variant: glue.TimeoutVariantBlockSync(c.Request)}}
	case *blocksync.CmdSendResponse:
		return []glue.Command{glue.RouterPublish{
			Target:  types.RouterTarget{Kind: types.RouterTcpPointToPoint, To: c.To},
			Message: &glue.VerifiedMonadMessage{Kind: 3, BlockSyncResponse: &c.Response},
		}}
	case *blocksync.CmdFetchHeaders:
		return []glue.Command{glue.LedgerFetchHeaders{Range: c.Range}}
	case *blocksync.CmdFetchPayload:
		return []glue.Command{glue.LedgerFetchPayload{BodyID: c.PayloadID}}
	case *blocksync.CmdEmit:
		var ev glue.MonadEvent
		if c.Requester == blocksync.SelfRequesterStateSync {
			ev = glue.EvStateSyncBlockSync{BlockRange: c.Range, FullBlocks: c.FullBlocks}
		} else {
			ev = glue.EvConsensusBlockSync{BlockRange: c.Range, FullBlocks: c.FullBlocks}
		}
		return []glue.Command{glue.LoopbackForward{Event: ev}}
	}
	return nil
}
