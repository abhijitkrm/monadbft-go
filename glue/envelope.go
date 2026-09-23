package glue

import (
	"github.com/abhijitkrm/monadbft-go/blocksync"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Envelope tags — Rust VerifiedMonadMessage/MonadMessage discriminants.
const (
	envConsensus         = 1
	envBlockSyncRequest  = 2
	envBlockSyncResponse = 3
	envForwardedTx       = 4
	envStateSync         = 5
)

// VerifiedMonadMessage — Rust VerifiedMonadMessage: the outbound envelope a
// node emits (already signature-verified + validated on the local node).
// Encoded as [monad_version, tag, payload].
type VerifiedMonadMessage struct {
	Kind uint8

	// Consensus (tag 1): a validated consensus message.
	Consensus *messages.Validated
	// BlockSyncRequest (tag 2)
	BlockSyncRequest *blocksync.RequestMessage
	// BlockSyncResponse (tag 3)
	BlockSyncResponse *blocksync.ResponseMessage
	// ForwardedTx (tag 4): forwarded tx bytes (<= MaxForwardedTxsPerMessage).
	ForwardedTx [][]byte
	// StateSyncMessage (tag 5)
	StateSyncMessage *StateSyncNetworkMessage
}

// VerifiedFromConsensus — Rust From<Verified<Validated>> for VerifiedMonadMessage.
func VerifiedFromConsensus(m messages.Validated) *VerifiedMonadMessage {
	return &VerifiedMonadMessage{Kind: envConsensus, Consensus: &m}
}

func (m *VerifiedMonadMessage) EncodeRLP(dst []byte) []byte {
	v := Version()
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = v.EncodeRLP(p)
		p = rlp.AppendUint8(p, m.Kind)
		switch m.Kind {
		case envConsensus:
			// Rust converts Verified<Validated> back into the Unverified wire form.
			p = m.Consensus.Verified.Message.EncodeRLP(p)
		case envBlockSyncRequest:
			p = m.BlockSyncRequest.EncodeRLP(p)
		case envBlockSyncResponse:
			p = m.BlockSyncResponse.EncodeRLP(p)
		case envForwardedTx:
			p = rlp.AppendList(p, func(q []byte) []byte {
				for _, tx := range m.ForwardedTx {
					q = rlp.AppendString(q, tx)
				}
				return q
			})
		case envStateSync:
			p = m.StateSyncMessage.EncodeRLP(p)
		}
		return p
	})
}

// Serialize — Rust Serializable<Bytes> for VerifiedMonadMessage.
func (m *VerifiedMonadMessage) Serialize() []byte { return m.EncodeRLP(nil) }

// ToMonadMessage — Rust From<VerifiedMonadMessage> for MonadMessage (drops the
// validated marker on Consensus back to Unverified for the wire/decode form).
func (m *VerifiedMonadMessage) ToMonadMessage() *MonadMessage {
	out := &MonadMessage{Kind: m.Kind}
	switch m.Kind {
	case envConsensus:
		out.Consensus = &m.Consensus.Verified.Message
	case envBlockSyncRequest:
		out.BlockSyncRequest = m.BlockSyncRequest
	case envBlockSyncResponse:
		out.BlockSyncResponse = m.BlockSyncResponse
	case envForwardedTx:
		out.ForwardedTx = m.ForwardedTx
	case envStateSync:
		out.StateSyncMessage = m.StateSyncMessage
	}
	return out
}

// MonadMessage — Rust MonadMessage: the inbound decode target (consensus
// message still Unverified). Decode is the entry point for inbound bytes.
type MonadMessage struct {
	Kind uint8

	Consensus         *messages.Unverified
	BlockSyncRequest  *blocksync.RequestMessage
	BlockSyncResponse *blocksync.ResponseMessage
	ForwardedTx       [][]byte
	StateSyncMessage  *StateSyncNetworkMessage
}

// DecodeMonadMessage — Rust MonadMessage::decode over the wire bytes.
func DecodeMonadMessage(data []byte, ep *exec.Protocol) (*MonadMessage, error) {
	s := rlp.NewStream(data)
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	var ver MonadVersion
	if err := ver.DecodeRLP(l); err != nil {
		return nil, err
	}
	tag, err := l.Uint64()
	if err != nil {
		return nil, err
	}
	m := &MonadMessage{Kind: uint8(tag)}
	switch tag {
	case envConsensus:
		var u messages.Unverified
		if err := u.DecodeRLP(l, ep); err != nil {
			return nil, err
		}
		m.Consensus = &u
	case envBlockSyncRequest:
		var r blocksync.RequestMessage
		if err := r.DecodeRLP(l); err != nil {
			return nil, err
		}
		m.BlockSyncRequest = &r
	case envBlockSyncResponse:
		var r blocksync.ResponseMessage
		if err := r.DecodeRLP(l, ep); err != nil {
			return nil, err
		}
		m.BlockSyncResponse = &r
	case envForwardedTx:
		ll, err := l.List()
		if err != nil {
			return nil, err
		}
		var txs [][]byte
		for ll.Remaining() > 0 {
			b, err := ll.Bytes()
			if err != nil {
				return nil, err
			}
			txs = append(txs, b)
		}
		if err := ll.Done(); err != nil {
			return nil, err
		}
		if len(txs) > MaxForwardedTxsPerMessage {
			return nil, rlp.ErrCustom
		}
		m.ForwardedTx = txs
	case envStateSync:
		var ss StateSyncNetworkMessage
		if err := ss.DecodeRLP(l); err != nil {
			return nil, err
		}
		m.StateSyncMessage = &ss
	default:
		return nil, rlp.ErrCustom
	}
	if err := l.Done(); err != nil {
		return nil, err
	}
	return m, nil
}

// Event — Rust MonadMessage::event(from): produce the MonadEvent the message
// decodes into. `from` is the transport-level sender (already known staked).
func (m *MonadMessage) Event(from types.NodeId) MonadEvent {
	switch m.Kind {
	case envConsensus:
		return EvConsensusMessage{Sender: from, UnverifiedMessage: *m.Consensus}
	case envBlockSyncRequest:
		return EvBlockSyncRequest{Sender: from, Request: *m.BlockSyncRequest}
	case envBlockSyncResponse:
		return EvBlockSyncResponse{Sender: from, Response: *m.BlockSyncResponse}
	case envForwardedTx:
		return EvMempoolForwardedTxs{Sender: from, Txs: m.ForwardedTx}
	case envStateSync:
		return EvStateSyncInbound{From: from, Message: *m.StateSyncMessage}
	}
	return nil
}
