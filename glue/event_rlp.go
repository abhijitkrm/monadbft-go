package glue

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/abhijitkrm/monadbft-go/blocksync"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

// IsWalLogged — Rust monad_wal::WALLog::is_wal_logged. Only consensus-critical
// events are appended to the WAL; control-panel/config/secondary-raptorcast
// events and non-deterministic inputs (statesync in/outbound, forwarded txs)
// are not logged.
func IsWalLogged(e MonadEvent) bool {
	switch e.(type) {
	case EvConsensusMessage, EvConsensusTimeout, EvConsensusBlockSync, EvConsensusSendVote,
		EvBlockSyncRequest, EvBlockSyncTimeout, EvBlockSyncSelfRequest,
		EvBlockSyncSelfCancelRequest, EvBlockSyncResponse, EvBlockSyncSelfResponse,
		EvUpdateValidators,
		EvMempoolProposal,
		EvStateSyncDoneSync, EvStateSyncBlockSync, EvStateSyncRequestSync,
		EvTimestampUpdate:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Supporting codecs for types declared in commands.go / events.go.
// ---------------------------------------------------------------------------

func (v ValidatorData) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = v.NodeId.EncodeRLP(p)
		p = v.Stake.EncodeRLP(p)
		p = rlp.AppendString(p, v.CertPubKey[:])
		return p
	})
}

func (v *ValidatorData) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := v.NodeId.DecodeRLP(l); err != nil {
		return err
	}
	if err := v.Stake.DecodeRLP(l); err != nil {
		return err
	}
	pk, err := l.FixedBytes(48)
	if err != nil {
		return err
	}
	copy(v.CertPubKey[:], pk)
	return l.Done()
}

func (v ValidatorSetData) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		return appendValidatorDataList(p, v.Validators)
	})
}

func appendValidatorDataList(dst []byte, vs []ValidatorData) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		for _, v := range vs {
			p = v.EncodeRLP(p)
		}
		return p
	})
}

func (v *ValidatorSetData) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	inner, err := l.List()
	if err != nil {
		return err
	}
	for inner.Remaining() > 0 {
		var vd ValidatorData
		if err := vd.DecodeRLP(inner); err != nil {
			return err
		}
		v.Validators = append(v.Validators, vd)
	}
	if err := inner.Done(); err != nil {
		return err
	}
	return l.Done()
}

func (v ValidatorSetDataWithEpoch) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = v.Epoch.EncodeRLP(p)
		p = v.Validators.EncodeRLP(p)
		return p
	})
}

func (v *ValidatorSetDataWithEpoch) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := v.Epoch.DecodeRLP(l); err != nil {
		return err
	}
	if err := v.Validators.DecodeRLP(l); err != nil {
		return err
	}
	return l.Done()
}

func (p ProposedExecutionInputs) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(b []byte) []byte {
		b = p.Header.EncodeRLP(b)
		b = p.Body.EncodeRLP(b)
		return b
	})
}

func (p *ProposedExecutionInputs) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	p.Header = ep.NewProposedHeader()
	if err := p.Header.DecodeRLP(l); err != nil {
		return err
	}
	p.Body = ep.NewBody()
	if err := p.Body.DecodeRLP(l); err != nil {
		return err
	}
	return l.Done()
}

func appendFinalizedHeaderList(dst []byte, hs []exec.FinalizedHeader) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		for _, h := range hs {
			p = h.EncodeRLP(p)
		}
		return p
	})
}

func decodeFinalizedHeaderList(s *rlp.Stream, ep *exec.Protocol) ([]exec.FinalizedHeader, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	var out []exec.FinalizedHeader
	for l.Remaining() > 0 {
		h := ep.NewFinalizedHeader()
		if err := h.DecodeRLP(l); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, l.Done()
}

func appendFullBlockList(dst []byte, bs []cstypes.ConsensusFullBlock) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		for _, b := range bs {
			p = b.EncodeRLP(p)
		}
		return p
	})
}

func decodeFullBlockList(s *rlp.Stream, ep *exec.Protocol) ([]cstypes.ConsensusFullBlock, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	var out []cstypes.ConsensusFullBlock
	for l.Remaining() > 0 {
		var b cstypes.ConsensusFullBlock
		if err := b.DecodeRLP(l, ep); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, l.Done()
}

func appendNodeIdList(dst []byte, ns []types.NodeId) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		for _, n := range ns {
			p = n.EncodeRLP(p)
		}
		return p
	})
}

func decodeNodeIdList(s *rlp.Stream) ([]types.NodeId, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	var out []types.NodeId
	for l.Remaining() > 0 {
		var n types.NodeId
		if err := n.DecodeRLP(l); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, l.Done()
}

func appendBytesList(dst []byte, xs [][]byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		for _, x := range xs {
			p = rlp.AppendString(p, x)
		}
		return p
	})
}

func decodeBytesList(s *rlp.Stream) ([][]byte, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for l.Remaining() > 0 {
		b, err := l.Bytes()
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, l.Done()
}

// ---------------------------------------------------------------------------
// EncodeMonadEvent — Rust Encodable for MonadEvent: [outer_tag, inner…].
// ---------------------------------------------------------------------------

func EncodeMonadEvent(e MonadEvent) ([]byte, error) {
	switch ev := e.(type) {
	case ConsensusEvent:
		inner, err := encodeConsensusEvent(ev)
		if err != nil {
			return nil, err
		}
		return wrapEvent(1, inner), nil
	case BlockSyncEvent:
		inner, err := encodeBlockSyncEvent(ev)
		if err != nil {
			return nil, err
		}
		return wrapEvent(2, inner), nil
	case ValidatorEvent:
		inner, err := encodeValidatorEvent(ev)
		if err != nil {
			return nil, err
		}
		return wrapEvent(3, inner), nil
	case MempoolEvent:
		inner, err := encodeMempoolEvent(ev)
		if err != nil {
			return nil, err
		}
		return wrapEvent(4, inner), nil
	case ControlPanelEvent:
		inner, err := encodeControlPanelEvent(ev)
		if err != nil {
			return nil, err
		}
		return wrapEvent(5, inner), nil
	case EvTimestampUpdate:
		return rlp.AppendList(nil, func(p []byte) []byte {
			p = rlp.AppendUint8(p, 6)
			p = ev.Timestamp.EncodeRLP(p)
			return p
		}), nil
	case StateSyncEvent:
		inner, err := encodeStateSyncEvent(ev)
		if err != nil {
			return nil, err
		}
		return wrapEvent(7, inner), nil
	case ConfigEvent:
		inner, err := encodeConfigEvent(ev)
		if err != nil {
			return nil, err
		}
		return wrapEvent(8, inner), nil
	case EvSecondaryRaptorcastPeersUpdate:
		return rlp.AppendList(nil, func(p []byte) []byte {
			p = rlp.AppendUint8(p, 9)
			p = ev.ExpiryRound.EncodeRLP(p)
			p = appendNodeIdList(p, ev.ConfirmGroupPeers)
			return p
		}), nil
	}
	return nil, fmt.Errorf("glue: unknown MonadEvent %T", e)
}

func wrapEvent(tag uint8, inner []byte) []byte {
	return rlp.AppendList(nil, func(p []byte) []byte {
		p = rlp.AppendUint8(p, tag)
		p = rlp.AppendRaw(p, inner)
		return p
	})
}

func encodeConsensusEvent(e ConsensusEvent) ([]byte, error) {
	return rlp.AppendList(nil, func(p []byte) []byte {
		switch ev := e.(type) {
		case EvConsensusMessage:
			p = rlp.AppendUint8(p, 1)
			p = ev.Sender.EncodeRLP(p)
			p = ev.UnverifiedMessage.EncodeRLP(p)
		case EvConsensusTimeout:
			p = rlp.AppendUint8(p, 2)
			p = ev.Round.EncodeRLP(p)
		case EvConsensusBlockSync:
			p = rlp.AppendUint8(p, 3)
			p = ev.BlockRange.EncodeRLP(p)
			p = appendFullBlockList(p, ev.FullBlocks)
		case EvConsensusSendVote:
			p = rlp.AppendUint8(p, 4)
			p = ev.Round.EncodeRLP(p)
		default:
			panic(fmt.Sprintf("glue: unknown ConsensusEvent %T", e))
		}
		return p
	}), nil
}

func encodeBlockSyncEvent(e BlockSyncEvent) ([]byte, error) {
	return rlp.AppendList(nil, func(p []byte) []byte {
		switch ev := e.(type) {
		case EvBlockSyncRequest:
			p = rlp.AppendUint8(p, 1)
			p = ev.Sender.EncodeRLP(p)
			p = ev.Request.EncodeRLP(p)
		case EvBlockSyncTimeout:
			p = rlp.AppendUint8(p, 2)
			p = ev.Request.EncodeRLP(p)
		case EvBlockSyncSelfRequest:
			p = rlp.AppendUint8(p, 3)
			p = ev.Requester.EncodeRLP(p)
			p = ev.BlockRange.EncodeRLP(p)
		case EvBlockSyncSelfCancelRequest:
			p = rlp.AppendUint8(p, 4)
			p = ev.Requester.EncodeRLP(p)
			p = ev.BlockRange.EncodeRLP(p)
		case EvBlockSyncResponse:
			p = rlp.AppendUint8(p, 5)
			p = ev.Sender.EncodeRLP(p)
			p = ev.Response.EncodeRLP(p)
		case EvBlockSyncSelfResponse:
			p = rlp.AppendUint8(p, 6)
			p = ev.Response.EncodeRLP(p)
		default:
			panic(fmt.Sprintf("glue: unknown BlockSyncEvent %T", e))
		}
		return p
	}), nil
}

func encodeValidatorEvent(e ValidatorEvent) ([]byte, error) {
	switch ev := e.(type) {
	case EvUpdateValidators:
		return rlp.AppendList(nil, func(p []byte) []byte {
			p = rlp.AppendUint8(p, 1)
			p = ev.ValidatorSetDataWithEpoch.EncodeRLP(p)
			return p
		}), nil
	}
	return nil, fmt.Errorf("glue: unknown ValidatorEvent %T", e)
}

// encodeOptList — Rust optional-field encoding: [1]=None, [2, val]=Some.
func encodeOptList(dst []byte, some bool, encode func(p []byte) []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		if some {
			p = rlp.AppendUint8(p, 2)
			p = encode(p)
		} else {
			p = rlp.AppendUint8(p, 1)
		}
		return p
	})
}

func encodeMempoolEvent(e MempoolEvent) ([]byte, error) {
	return rlp.AppendList(nil, func(p []byte) []byte {
		switch ev := e.(type) {
		case EvMempoolProposal:
			p = rlp.AppendUint8(p, 1)
			p = ev.Epoch.EncodeRLP(p)
			p = ev.Round.EncodeRLP(p)
			p = ev.SeqNum.EncodeRLP(p)
			p = ev.HighQC.EncodeRLP(p)
			p = ev.TimestampNs.EncodeRLP(p)
			p = rlp.AppendString(p, ev.RoundSignature.Compress())
			p = rlp.AppendUint64(p, ev.BaseFee)
			p = rlp.AppendUint64(p, ev.BaseFeeTrend)
			p = rlp.AppendUint64(p, ev.BaseFeeMoment)
			p = appendFinalizedHeaderList(p, ev.DelayedExecutionResults)
			p = ev.ProposedExecutionInputs.EncodeRLP(p)
			p = encodeOptList(p, ev.LastRoundTC != nil, func(q []byte) []byte {
				return ev.LastRoundTC.EncodeRLP(q)
			})
			p = encodeOptList(p, ev.FreshProposalCertificate != nil, func(q []byte) []byte {
				return ev.FreshProposalCertificate.EncodeRLP(q)
			})
		case EvMempoolForwardedTxs:
			p = rlp.AppendUint8(p, 2)
			p = ev.Sender.EncodeRLP(p)
			p = appendBytesList(p, ev.Txs)
		case EvMempoolForwardTxs:
			p = rlp.AppendUint8(p, 3)
			p = appendBytesList(p, ev.Txs)
		default:
			panic(fmt.Sprintf("glue: unknown MempoolEvent %T", e))
		}
		return p
	}), nil
}

func encodeControlPanelEvent(e ControlPanelEvent) ([]byte, error) {
	return rlp.AppendList(nil, func(p []byte) []byte {
		switch ev := e.(type) {
		case EvGetMetrics:
			p = rlp.AppendUint8(p, 2)
		case EvClearMetrics:
			p = rlp.AppendUint8(p, 3)
		case EvUpdateLogFilter:
			p = rlp.AppendUint8(p, 5)
			p = rlp.AppendString(p, []byte(ev.Filter))
		case EvGetPeers:
			p = rlp.AppendUint8(p, 6)
			// Rust: Request=[1], Response=[2] (peer list elided).
			if ev.Peers.Request {
				p = rlp.AppendList(p, func(q []byte) []byte { return rlp.AppendUint8(q, 1) })
			} else {
				p = rlp.AppendList(p, func(q []byte) []byte { return rlp.AppendUint8(q, 2) })
			}
		case EvGetFullNodes:
			p = rlp.AppendUint8(p, 7)
			if ev.FullNodes.Request {
				p = rlp.AppendList(p, func(q []byte) []byte { return rlp.AppendUint8(q, 1) })
			} else {
				p = rlp.AppendList(p, func(q []byte) []byte { return rlp.AppendUint8(q, 2) })
			}
		case EvReloadConfig:
			p = rlp.AppendUint8(p, 8)
			if ev.Request {
				p = rlp.AppendList(p, func(q []byte) []byte { return rlp.AppendUint8(q, 1) })
			} else {
				p = rlp.AppendList(p, func(q []byte) []byte {
					q = rlp.AppendUint8(q, 2)
					return rlp.AppendString(q, []byte(ev.Response))
				})
			}
		default:
			panic(fmt.Sprintf("glue: unknown ControlPanelEvent %T", e))
		}
		return p
	}), nil
}

func encodeStateSyncEvent(e StateSyncEvent) ([]byte, error) {
	return rlp.AppendList(nil, func(p []byte) []byte {
		switch ev := e.(type) {
		case EvStateSyncInbound:
			p = rlp.AppendUint8(p, 1)
			p = ev.From.EncodeRLP(p)
			p = ev.Message.EncodeRLP(p)
		case EvStateSyncOutbound:
			p = rlp.AppendUint8(p, 2)
			p = ev.To.EncodeRLP(p)
			p = ev.Message.EncodeRLP(p)
		case EvStateSyncDoneSync:
			p = rlp.AppendUint8(p, 3)
			p = ev.SeqNum.EncodeRLP(p)
		case EvStateSyncBlockSync:
			p = rlp.AppendUint8(p, 4)
			p = ev.BlockRange.EncodeRLP(p)
			p = appendFullBlockList(p, ev.FullBlocks)
		case EvStateSyncRequestSync:
			p = rlp.AppendUint8(p, 5)
			p = ev.Root.EncodeRLP(p)
			p = ev.HighQC.EncodeRLP(p)
		default:
			panic(fmt.Sprintf("glue: unknown StateSyncEvent %T", e))
		}
		return p
	}), nil
}

func encodeConfigEvent(e ConfigEvent) ([]byte, error) {
	return rlp.AppendList(nil, func(p []byte) []byte {
		switch ev := e.(type) {
		case EvConfigUpdate:
			p = rlp.AppendUint8(p, 1)
			p = ev.Update.EncodeRLP(p)
		case EvKnownPeersUpdate:
			p = rlp.AppendUint8(p, 2)
			p = ev.Update.EncodeRLP(p)
		case EvConfigLoadError:
			p = rlp.AppendUint8(p, 3)
			p = rlp.AppendString(p, []byte(ev.Err))
		default:
			panic(fmt.Sprintf("glue: unknown ConfigEvent %T", e))
		}
		return p
	}), nil
}

// ConfigUpdate — Rust ConfigUpdate (RlpEncodable struct).
func (c ConfigUpdate) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = appendNodeIdList(p, c.DedicatedFullNodes)
		p = appendNodeIdList(p, c.PrioritizedFullNodes)
		p = appendNodeIdList(p, c.BlocksyncOverridePeers)
		return p
	})
}

func (c *ConfigUpdate) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if c.DedicatedFullNodes, err = decodeNodeIdList(l); err != nil {
		return err
	}
	if c.PrioritizedFullNodes, err = decodeNodeIdList(l); err != nil {
		return err
	}
	if c.BlocksyncOverridePeers, err = decodeNodeIdList(l); err != nil {
		return err
	}
	return l.Done()
}

// KnownPeersUpdate — Rust KnownPeersUpdate (RlpEncodable). Our PeerEntry is a
// minimal port (no socket address / signature fields); this event is never
// WAL-logged nor sent on the consensus wire.
func (k KnownPeersUpdate) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = appendPeerEntryList(p, k.KnownPeers)
		p = appendNodeIdList(p, k.DedicatedFullNodes)
		p = appendNodeIdList(p, k.PrioritizedFullNodes)
		return p
	})
}

func (k *KnownPeersUpdate) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if k.KnownPeers, err = decodePeerEntryList(l); err != nil {
		return err
	}
	if k.DedicatedFullNodes, err = decodeNodeIdList(l); err != nil {
		return err
	}
	if k.PrioritizedFullNodes, err = decodeNodeIdList(l); err != nil {
		return err
	}
	return l.Done()
}

// PeerEntry minimal codec — Rust encodes [pubkey, ip-string, signature,
// record_seq_num, auth_port, direct_udp_port, tcp_port, udp_port,
// encrypted_tcp_port]. Our port carries only (pubkey-as-nodeid, seq, auth_port)
// so we encode [pubkey, record_seq_num, auth_port] — a divergent but
// self-consistent layout used only for the never-logged KnownPeersUpdate.
func (e PeerEntry) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = e.Pubkey.EncodeRLP(p)
		p = rlp.AppendUint64(p, e.RecordSeqNum)
		p = rlp.AppendUint64(p, uint64(e.AuthPort))
		return p
	})
}

func (e *PeerEntry) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := e.Pubkey.DecodeRLP(l); err != nil {
		return err
	}
	seq, err := l.Uint64()
	if err != nil {
		return err
	}
	e.RecordSeqNum = seq
	port, err := l.Uint64()
	if err != nil {
		return err
	}
	e.AuthPort = uint16(port)
	return l.Done()
}

func appendPeerEntryList(dst []byte, es []PeerEntry) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		for _, e := range es {
			p = e.EncodeRLP(p)
		}
		return p
	})
}

func decodePeerEntryList(s *rlp.Stream) ([]PeerEntry, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	var out []PeerEntry
	for l.Remaining() > 0 {
		var e PeerEntry
		if err := e.DecodeRLP(l); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, l.Done()
}

// ---------------------------------------------------------------------------
// DecodeMonadEvent — Rust Decodable for MonadEvent.
// ---------------------------------------------------------------------------

func DecodeMonadEvent(data []byte, ep *exec.Protocol) (MonadEvent, error) {
	s := rlp.NewStream(data)
	payload, err := s.List()
	if err != nil {
		return nil, err
	}
	tag, err := payload.Uint64()
	if err != nil {
		return nil, err
	}
	var ev MonadEvent
	switch tag {
	case 1:
		ev, err = decodeConsensusEvent(payload, ep)
	case 2:
		ev, err = decodeBlockSyncEvent(payload, ep)
	case 3:
		ev, err = decodeValidatorEvent(payload)
	case 4:
		ev, err = decodeMempoolEvent(payload, ep)
	case 5:
		ev, err = decodeControlPanelEvent(payload)
	case 6:
		var ts types.U128
		err = ts.DecodeRLP(payload)
		ev = EvTimestampUpdate{Timestamp: ts}
	case 7:
		ev, err = decodeStateSyncEvent(payload, ep)
	case 8:
		ev, err = decodeConfigEvent(payload)
	case 9:
		var round types.Round
		if err = round.DecodeRLP(payload); err == nil {
			var peers []types.NodeId
			peers, err = decodeNodeIdList(payload)
			ev = EvSecondaryRaptorcastPeersUpdate{ExpiryRound: round, ConfirmGroupPeers: peers}
		}
	default:
		return nil, fmt.Errorf("glue: unknown MonadEvent tag %d", tag)
	}
	if err != nil {
		return nil, err
	}
	if err := payload.Done(); err != nil {
		return nil, err
	}
	return ev, s.Done()
}

func decodeConsensusEvent(s *rlp.Stream, ep *exec.Protocol) (MonadEvent, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	tag, err := l.Uint64()
	if err != nil {
		return nil, err
	}
	var ev MonadEvent
	switch tag {
	case 1:
		var sender types.NodeId
		if err := sender.DecodeRLP(l); err != nil {
			return nil, err
		}
		var msg messages.Unverified
		if err := msg.DecodeRLP(l, ep); err != nil {
			return nil, err
		}
		ev = EvConsensusMessage{Sender: sender, UnverifiedMessage: msg}
	case 2:
		var round types.Round
		if err := round.DecodeRLP(l); err != nil {
			return nil, err
		}
		ev = EvConsensusTimeout{Round: round}
	case 3:
		var br cstypes.BlockRange
		if err := br.DecodeRLP(l); err != nil {
			return nil, err
		}
		blocks, err := decodeFullBlockList(l, ep)
		if err != nil {
			return nil, err
		}
		ev = EvConsensusBlockSync{BlockRange: br, FullBlocks: blocks}
	case 4:
		var round types.Round
		if err := round.DecodeRLP(l); err != nil {
			return nil, err
		}
		ev = EvConsensusSendVote{Round: round}
	default:
		return nil, fmt.Errorf("glue: unknown ConsensusEvent tag %d", tag)
	}
	return ev, l.Done()
}

func decodeBlockSyncEvent(s *rlp.Stream, ep *exec.Protocol) (MonadEvent, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	tag, err := l.Uint64()
	if err != nil {
		return nil, err
	}
	var ev MonadEvent
	switch tag {
	case 1:
		var sender types.NodeId
		if err := sender.DecodeRLP(l); err != nil {
			return nil, err
		}
		var req blocksync.RequestMessage
		if err := req.DecodeRLP(l); err != nil {
			return nil, err
		}
		ev = EvBlockSyncRequest{Sender: sender, Request: req}
	case 2:
		var req blocksync.RequestMessage
		if err := req.DecodeRLP(l); err != nil {
			return nil, err
		}
		ev = EvBlockSyncTimeout{Request: req}
	case 3:
		var requester blocksync.SelfRequester
		if err := requester.DecodeRLP(l); err != nil {
			return nil, err
		}
		var br cstypes.BlockRange
		if err := br.DecodeRLP(l); err != nil {
			return nil, err
		}
		ev = EvBlockSyncSelfRequest{Requester: requester, BlockRange: br}
	case 4:
		var requester blocksync.SelfRequester
		if err := requester.DecodeRLP(l); err != nil {
			return nil, err
		}
		var br cstypes.BlockRange
		if err := br.DecodeRLP(l); err != nil {
			return nil, err
		}
		ev = EvBlockSyncSelfCancelRequest{Requester: requester, BlockRange: br}
	case 5:
		var sender types.NodeId
		if err := sender.DecodeRLP(l); err != nil {
			return nil, err
		}
		var resp blocksync.ResponseMessage
		if err := resp.DecodeRLP(l, ep); err != nil {
			return nil, err
		}
		ev = EvBlockSyncResponse{Sender: sender, Response: resp}
	case 6:
		var resp blocksync.ResponseMessage
		if err := resp.DecodeRLP(l, ep); err != nil {
			return nil, err
		}
		ev = EvBlockSyncSelfResponse{Response: resp}
	default:
		return nil, fmt.Errorf("glue: unknown BlockSyncEvent tag %d", tag)
	}
	return ev, l.Done()
}

func decodeValidatorEvent(s *rlp.Stream) (MonadEvent, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	tag, err := l.Uint64()
	if err != nil {
		return nil, err
	}
	switch tag {
	case 1:
		var vset ValidatorSetDataWithEpoch
		if err := vset.DecodeRLP(l); err != nil {
			return nil, err
		}
		return EvUpdateValidators{ValidatorSetDataWithEpoch: vset}, l.Done()
	}
	return nil, fmt.Errorf("glue: unknown ValidatorEvent tag %d", tag)
}

func decodeMempoolEvent(s *rlp.Stream, ep *exec.Protocol) (MonadEvent, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	tag, err := l.Uint64()
	if err != nil {
		return nil, err
	}
	switch tag {
	case 1:
		var ev EvMempoolProposal
		if err := ev.Epoch.DecodeRLP(l); err != nil {
			return nil, err
		}
		if err := ev.Round.DecodeRLP(l); err != nil {
			return nil, err
		}
		if err := ev.SeqNum.DecodeRLP(l); err != nil {
			return nil, err
		}
		if err := ev.HighQC.DecodeRLP(l); err != nil {
			return nil, err
		}
		if err := ev.TimestampNs.DecodeRLP(l); err != nil {
			return nil, err
		}
		sigB, err := l.FixedBytes(crypto.BlsSignatureCompressdLen)
		if err != nil {
			return nil, err
		}
		sig, err := crypto.BlsSignatureUncompress(sigB)
		if err != nil {
			return nil, err
		}
		ev.RoundSignature = sig
		if ev.BaseFee, err = l.Uint64(); err != nil {
			return nil, err
		}
		if ev.BaseFeeTrend, err = l.Uint64(); err != nil {
			return nil, err
		}
		if ev.BaseFeeMoment, err = l.Uint64(); err != nil {
			return nil, err
		}
		if ev.DelayedExecutionResults, err = decodeFinalizedHeaderList(l, ep); err != nil {
			return nil, err
		}
		if err := ev.ProposedExecutionInputs.DecodeRLP(l, ep); err != nil {
			return nil, err
		}
		if ev.LastRoundTC, err = decodeOptTC(l, ep); err != nil {
			return nil, err
		}
		if ev.FreshProposalCertificate, err = decodeOptFPC(l, ep); err != nil {
			return nil, err
		}
		return ev, l.Done()
	case 2:
		var sender types.NodeId
		if err := sender.DecodeRLP(l); err != nil {
			return nil, err
		}
		txs, err := decodeBytesList(l)
		if err != nil {
			return nil, err
		}
		return EvMempoolForwardedTxs{Sender: sender, Txs: txs}, l.Done()
	case 3:
		txs, err := decodeBytesList(l)
		if err != nil {
			return nil, err
		}
		return EvMempoolForwardTxs{Txs: txs}, l.Done()
	}
	return nil, fmt.Errorf("glue: unknown MempoolEvent tag %d", tag)
}

func decodeOptTag(l *rlp.Stream) (bool, error) {
	tag, err := l.Uint64()
	if err != nil {
		return false, err
	}
	switch tag {
	case 1:
		return false, nil
	case 2:
		return true, nil
	}
	return false, fmt.Errorf("glue: unknown optional tag %d", tag)
}

func decodeOptTC(s *rlp.Stream, ep *exec.Protocol) (*cstypes.TimeoutCertificate, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	some, err := decodeOptTag(l)
	if err != nil {
		return nil, err
	}
	if !some {
		return nil, l.Done()
	}
	var tc cstypes.TimeoutCertificate
	if err := tc.DecodeRLP(l, ep); err != nil {
		return nil, err
	}
	return &tc, l.Done()
}

func decodeOptFPC(s *rlp.Stream, ep *exec.Protocol) (*cstypes.FreshProposalCertificate, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	some, err := decodeOptTag(l)
	if err != nil {
		return nil, err
	}
	if !some {
		return nil, l.Done()
	}
	var fpc cstypes.FreshProposalCertificate
	if err := fpc.DecodeRLP(l, ep); err != nil {
		return nil, err
	}
	return &fpc, l.Done()
}

func decodeControlPanelEvent(s *rlp.Stream) (MonadEvent, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	tag, err := l.Uint64()
	if err != nil {
		return nil, err
	}
	switch tag {
	case 2:
		return EvGetMetrics{}, l.Done()
	case 3:
		return EvClearMetrics{}, l.Done()
	case 5:
		f, err := l.Bytes()
		if err != nil {
			return nil, err
		}
		return EvUpdateLogFilter{Filter: string(f)}, l.Done()
	case 6:
		req, err := decodeRequestMarker(l)
		if err != nil {
			return nil, err
		}
		return EvGetPeers{Peers: GetPeers{Request: req}}, l.Done()
	case 7:
		req, err := decodeRequestMarker(l)
		if err != nil {
			return nil, err
		}
		return EvGetFullNodes{FullNodes: GetFullNodes{Request: req}}, l.Done()
	case 8:
		sub, err := l.List()
		if err != nil {
			return nil, err
		}
		stag, err := sub.Uint64()
		if err != nil {
			return nil, err
		}
		switch stag {
		case 1:
			if err := sub.Done(); err != nil {
				return nil, err
			}
			return EvReloadConfig{Request: true}, l.Done()
		case 2:
			r, err := sub.Bytes()
			if err != nil {
				return nil, err
			}
			if err := sub.Done(); err != nil {
				return nil, err
			}
			return EvReloadConfig{Response: string(r)}, l.Done()
		}
		return nil, fmt.Errorf("glue: unknown ReloadConfig tag %d", stag)
	}
	return nil, fmt.Errorf("glue: unknown ControlPanelEvent tag %d", tag)
}

// decodeRequestMarker — Rust [1]=Request / [2]=Response marker lists.
func decodeRequestMarker(s *rlp.Stream) (bool, error) {
	sub, err := s.List()
	if err != nil {
		return false, err
	}
	tag, err := sub.Uint64()
	if err != nil {
		return false, err
	}
	if err := sub.Done(); err != nil {
		return false, err
	}
	switch tag {
	case 1:
		return true, nil
	case 2:
		return false, nil
	}
	return false, fmt.Errorf("glue: unknown request marker tag %d", tag)
}

func decodeStateSyncEvent(s *rlp.Stream, ep *exec.Protocol) (MonadEvent, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	tag, err := l.Uint64()
	if err != nil {
		return nil, err
	}
	switch tag {
	case 1:
		var from types.NodeId
		if err := from.DecodeRLP(l); err != nil {
			return nil, err
		}
		var msg StateSyncNetworkMessage
		if err := msg.DecodeRLP(l); err != nil {
			return nil, err
		}
		return EvStateSyncInbound{From: from, Message: msg}, l.Done()
	case 2:
		var to types.NodeId
		if err := to.DecodeRLP(l); err != nil {
			return nil, err
		}
		var msg StateSyncNetworkMessage
		if err := msg.DecodeRLP(l); err != nil {
			return nil, err
		}
		return EvStateSyncOutbound{To: to, Message: msg}, l.Done()
	case 3:
		var seq types.SeqNum
		if err := seq.DecodeRLP(l); err != nil {
			return nil, err
		}
		return EvStateSyncDoneSync{SeqNum: seq}, l.Done()
	case 4:
		var br cstypes.BlockRange
		if err := br.DecodeRLP(l); err != nil {
			return nil, err
		}
		blocks, err := decodeFullBlockList(l, ep)
		if err != nil {
			return nil, err
		}
		return EvStateSyncBlockSync{BlockRange: br, FullBlocks: blocks}, l.Done()
	case 5:
		var root cstypes.ConsensusBlockHeader
		if err := root.DecodeRLP(l, ep); err != nil {
			return nil, err
		}
		var qc cstypes.QuorumCertificate
		if err := qc.DecodeRLP(l); err != nil {
			return nil, err
		}
		return EvStateSyncRequestSync{Root: root, HighQC: qc}, l.Done()
	}
	return nil, fmt.Errorf("glue: unknown StateSyncEvent tag %d", tag)
}

func decodeConfigEvent(s *rlp.Stream) (MonadEvent, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	tag, err := l.Uint64()
	if err != nil {
		return nil, err
	}
	switch tag {
	case 1:
		var u ConfigUpdate
		if err := u.DecodeRLP(l); err != nil {
			return nil, err
		}
		return EvConfigUpdate{Update: u}, l.Done()
	case 2:
		var u KnownPeersUpdate
		if err := u.DecodeRLP(l); err != nil {
			return nil, err
		}
		return EvKnownPeersUpdate{Update: u}, l.Done()
	case 3:
		m, err := l.Bytes()
		if err != nil {
			return nil, err
		}
		return EvConfigLoadError{Err: string(m)}, l.Done()
	}
	return nil, fmt.Errorf("glue: unknown ConfigEvent tag %d", tag)
}

// ---------------------------------------------------------------------------
// LogFriendlyMonadEvent — Rust LogFriendlyMonadEvent { timestamp, event }.
// WAL payload = [u32le ts_len][bincode DateTime<Utc>][rlp MonadEvent].
// bincode encodes chrono's non-human-readable DateTime as (secs i64, nanos
// u32), both little-endian fixed-width.
// ---------------------------------------------------------------------------

const logFriendlyTsLen = 12 // i64 secs + u32 nanos

type LogFriendlyMonadEvent struct {
	Timestamp time.Time
	Event     MonadEvent
}

func (l LogFriendlyMonadEvent) Serialize() ([]byte, error) {
	eventBytes, err := EncodeMonadEvent(l.Event)
	if err != nil {
		return nil, err
	}
	ts := make([]byte, logFriendlyTsLen)
	binary.LittleEndian.PutUint64(ts[0:8], uint64(l.Timestamp.Unix()))
	binary.LittleEndian.PutUint32(ts[8:12], uint32(l.Timestamp.Nanosecond()))
	out := make([]byte, 0, 4+len(ts)+len(eventBytes))
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(ts)))
	out = append(out, lenBuf[:]...)
	out = append(out, ts...)
	out = append(out, eventBytes...)
	return out, nil
}

// DeserializeTimestamp — Rust LogFriendlyMonadEvent::deserialize_timestamp.
func DeserializeTimestamp(data []byte) (time.Time, error) {
	if len(data) < 4 {
		return time.Time{}, fmt.Errorf("glue: short log-friendly event")
	}
	tsLen := int(binary.LittleEndian.Uint32(data[0:4]))
	if len(data) < 4+tsLen || tsLen < logFriendlyTsLen {
		return time.Time{}, fmt.Errorf("glue: short timestamp payload")
	}
	secs := int64(binary.LittleEndian.Uint64(data[4:12]))
	nanos := int64(binary.LittleEndian.Uint32(data[12:16]))
	return time.Unix(secs, nanos).UTC(), nil
}

// DeserializeLogFriendly — Rust Deserializable for LogFriendlyMonadEvent.
func DeserializeLogFriendly(data []byte, ep *exec.Protocol) (LogFriendlyMonadEvent, error) {
	if len(data) < 4 {
		return LogFriendlyMonadEvent{}, fmt.Errorf("glue: short log-friendly event")
	}
	tsLen := int(binary.LittleEndian.Uint32(data[0:4]))
	if len(data) < 4+tsLen {
		return LogFriendlyMonadEvent{}, fmt.Errorf("glue: short timestamp payload")
	}
	ts, err := DeserializeTimestamp(data[:4+tsLen])
	if err != nil {
		return LogFriendlyMonadEvent{}, err
	}
	ev, err := DecodeMonadEvent(data[4+tsLen:], ep)
	if err != nil {
		return LogFriendlyMonadEvent{}, err
	}
	return LogFriendlyMonadEvent{Timestamp: ts, Event: ev}, nil
}
