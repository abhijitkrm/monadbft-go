package raptorcast

import (
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// udpState — Rust udp.rs UdpState: receive-side chunk dispatch, decoding,
// and rebroadcast decisions for a validator node.

const signatureVerificationRateDefault = 10_000 // per second

type udpState struct {
	selfID       types.NodeId
	selfIDHash   NodeIdHash
	verifier     *signatureVerifier
	decoderCache *decoderCache
	maxAgeMs     uint64
}

// recvUDPMessage mirrors Rust AuthRecvMsg essentials: the datagram payload
// plus the authenticated sender (when known via wireauth) and stride.
type recvUDPMessage struct {
	srcAddr string
	sender  *types.NodeId // authenticated sender, if known
	stride  int           // chunk stride for batched datagrams
	payload []byte
}

func newUDPState(selfID types.NodeId, maxAgeMs uint64, sigRatePerSec uint32) *udpState {
	return &udpState{
		selfID:       selfID,
		selfIDHash:   computeHash(selfID),
		verifier:     newSignatureVerifier(SignatureCacheSize, sigRatePerSec),
		decoderCache: newDecoderCache(defaultDecoderCacheConfig),
		maxAgeMs:     maxAgeMs,
	}
}

// rebroadcastRequest pairs rebroadcast targets with the original packet
// bytes (Rust BroadcastBatcher output).
type rebroadcastRequest struct {
	targets []types.NodeId
	payload []byte
	stride  uint16
}

// handleMessage — Rust UdpState::handle_message: split the datagram by
// stride, parse + validate each chunk, dispatch, collect decoded app
// messages and rebroadcast requests.
func (s *udpState) handleMessage(
	epochValidators map[types.Epoch]*validator.ValidatorSet,
	message recvUDPMessage,
	rebroadcast func(rebroadcastRequest),
) []struct {
	Author  types.NodeId
	Payload []byte
} {
	var messages []struct {
		Author  types.NodeId
		Payload []byte
	}
	if message.stride <= 0 {
		message.stride = len(message.payload)
	}
	for start := 0; start < len(message.payload); start += message.stride {
		end := start + message.stride
		if end > len(message.payload) {
			end = len(message.payload)
		}
		payload := message.payload[start:end]

		bypassRateLimiter := func(epoch types.Epoch) bool {
			if message.sender == nil {
				return false
			}
			vs := epochValidators[epoch]
			return vs != nil && vs.IsMember(*message.sender)
		}

		pkt, err := parsePacket(payload)
		if err != nil {
			continue
		}
		chk, err := pkt.validateChunk(payload, s.verifier, s.maxAgeMs, bypassRateLimiter, s.selfID)
		if err != nil {
			continue
		}

		rebroadcastTo := func(targets []types.NodeId) {
			if rebroadcast != nil && len(targets) > 0 {
				rebroadcast(rebroadcastRequest{
					targets: targets,
					payload: payload,
					stride:  uint16(end - start),
				})
			}
		}

		var decoded *decodedResult
		switch chk.broadcastMode {
		case BroadcastUnspecified:
			decoded = s.handleUnicast(epochValidators, chk)
		case BroadcastPrimary:
			decoded = s.handleRaptorcast(epochValidators, chk, message.sender, rebroadcastTo)
		default:
			// BroadcastSecondary handled by B5.
			continue
		}
		if decoded != nil && decoded.status == statusDecoded {
			messages = append(messages, struct {
				Author  types.NodeId
				Payload []byte
			}{decoded.author, decoded.appMessage})
		}
	}
	return messages
}

// handleUnicast — Rust UdpState::handle_unicast: the recipient hash must
// equal our own node hash (anti-spoof), then decode.
func (s *udpState) handleUnicast(epochValidators map[types.Epoch]*validator.ValidatorSet, chk *validatedChunk) *decodedResult {
	if chk.recipientHash == nil || *chk.recipientHash != s.selfIDHash {
		return nil
	}
	var vs *validator.ValidatorSet
	if !chk.groupID.IsSecondary {
		vs = epochValidators[types.Epoch(chk.groupID.N)]
	}
	res, err := s.decoderCache.tryDecode(chk, vs, unixTsMsNow())
	if err != nil {
		return nil
	}
	if res.status == statusDecoded && chk.appMessageHash != nil {
		if computeAppMessageHash(res.appMessage) != *chk.appMessageHash {
			s.decoderCache.markTainted(chk)
			return nil
		}
	}
	return &res
}

// handleRaptorcast — Rust UdpState::handle_raptorcast + handle_regular for
// the primary group path.
func (s *udpState) handleRaptorcast(
	epochValidators map[types.Epoch]*validator.ValidatorSet,
	chk *validatedChunk,
	sender *types.NodeId,
	rebroadcastTo func([]types.NodeId),
) *decodedResult {
	if chk.groupID.IsSecondary {
		return nil // secondary handled by B5
	}
	group, err := primaryGroupOfEpoch(types.Epoch(chk.groupID.N), chk.author, epochValidators)
	if err != nil {
		return nil
	}
	if sender != nil && !group.isSenderValid(*sender) {
		return nil
	}
	vs := group.group
	res, err := s.decoderCache.tryDecode(chk, vs, unixTsMsNow())
	if err != nil {
		return nil
	}
	if res.status == statusDecoded && chk.appMessageHash != nil {
		if computeAppMessageHash(res.appMessage) != *chk.appMessageHash {
			s.decoderCache.markTainted(chk)
			return nil
		}
	}
	// regular rebroadcast: first-hop recipients rebroadcast to the group.
	isFirstHop := chk.recipientHash != nil && *chk.recipientHash == s.selfIDHash
	if targets := group.tryRebroadcast(s.selfID, isFirstHop); len(targets) > 0 {
		rebroadcastTo(targets)
	}
	return &res
}
