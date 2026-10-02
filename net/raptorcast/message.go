package raptorcast

import (
	"errors"
	"fmt"

	"github.com/abhijitkrm/monadbft-go/rlp"
)

// Router message envelope — ports monad-raptorcast message.rs:
// OutboundRouterMessage serializes to RLP [[1, 1], type, payload] where the
// inner list is NetworkMessageVersion {serialize_version=1,
// compression_version=1(uncompressed)}. Only the AppMessage variant is
// needed on the primary path.

var ErrUnknownMessageType = errors.New("unknown router message type")
var ErrExtraData = errors.New("extra data in message")

const (
	messageTypeApp      = 1
	messageTypePeerDisc = 2
	messageTypeGroup    = 3
)

// encodeAppMessageEnvelope wraps an RLP-encoded app message into the
// router envelope: [[1, 1], 0x01, <app message rlp>].
func encodeAppMessageEnvelope(appMessageRLP []byte) ([]byte, error) {
	return encodeEnvelope(messageTypeApp, appMessageRLP)
}

// encodePeerDiscoveryEnvelope — OutboundRouterMessage::PeerDiscoveryMessage:
// [[1, 1], 0x02, <peerdisc message rlp>].
func encodePeerDiscoveryEnvelope(msgRLP []byte) ([]byte, error) {
	return encodeEnvelope(messageTypePeerDisc, msgRLP)
}

func encodeEnvelope(kind uint8, msgRLP []byte) ([]byte, error) {
	if len(msgRLP) == 0 {
		return nil, ErrAppMessageEmpty
	}
	out := rlp.AppendList(nil, func(p []byte) []byte {
		p = rlp.AppendList(p, func(v []byte) []byte {
			v = rlp.AppendUint32(v, 1) // serialize_version
			v = rlp.AppendUint8(v, 1)  // compression_version: uncompressed
			return v
		})
		p = rlp.AppendUint8(p, kind)
		p = rlp.AppendRaw(p, msgRLP)
		return p
	})
	if len(out) > MaxMessageSize {
		return nil, ErrAppMessageTooLarge
	}
	return out, nil
}

// decodedRouterMessage is an inbound envelope split into kind + payload.
type decodedRouterMessage struct {
	kind    uint8
	payload []byte // raw RLP of the app message
}

// decodeRouterEnvelope — Rust InboundRouterMessage::try_deserialize
// (uncompressed only; returns the raw inner RLP for the caller to decode).
func decodeRouterEnvelope(data []byte) (*decodedRouterMessage, error) {
	if len(data) > MaxMessageSize {
		return nil, fmt.Errorf("%w: %d", ErrAppMessageTooLarge, len(data))
	}
	var out *decodedRouterMessage
	err := rlp.DecodeExact(data, func(outer *rlp.Stream) error {
		s, err := outer.List()
		if err != nil {
			return err
		}
		ver, err := s.List()
		if err != nil {
			return err
		}
		// NetworkMessageVersion { serialize_version, compression_version }
		if _, err := ver.Uint32(); err != nil {
			return err
		}
		compression, err := ver.Uint8()
		if err != nil {
			return err
		}
		if compression != 1 {
			return fmt.Errorf("%w: zstd compression not enabled", ErrUnknownMessageType)
		}
		if err := ver.Done(); err != nil {
			return err
		}
		kind, err := s.Uint8()
		if err != nil {
			return err
		}
		if kind != messageTypeApp && kind != messageTypePeerDisc && kind != messageTypeGroup {
			return fmt.Errorf("%w: %d", ErrUnknownMessageType, kind)
		}
		// remaining stream bytes = the app message element
		raw := s.Raw()
		// split off exactly one RLP item
		itemLen, err := rlpItemLen(raw)
		if err != nil {
			return err
		}
		if itemLen != len(raw) {
			return ErrExtraData
		}
		out = &decodedRouterMessage{kind: kind, payload: raw[:itemLen]}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Exported envelope accessors for the composite node transport — the TCP
// fallback signs and carries the same [[1,1],kind,payload] envelope as UDP.
const (
	MessageTypeApp      = messageTypeApp
	MessageTypePeerDisc = messageTypePeerDisc
	MessageTypeGroup    = messageTypeGroup
)

// EncodeAppMessageEnvelope wraps an RLP-encoded app message (kind 1).
func EncodeAppMessageEnvelope(msgRLP []byte) ([]byte, error) {
	return encodeAppMessageEnvelope(msgRLP)
}

// EncodePeerDiscoveryEnvelope wraps an RLP-encoded PeerDiscoveryMessage
// (kind 2).
func EncodePeerDiscoveryEnvelope(msgRLP []byte) ([]byte, error) {
	return encodePeerDiscoveryEnvelope(msgRLP)
}

// DecodeRouterEnvelope — InboundRouterMessage::try_deserialize; returns the
// message kind and the raw inner RLP payload.
func DecodeRouterEnvelope(data []byte) (uint8, []byte, error) {
	m, err := decodeRouterEnvelope(data)
	if err != nil {
		return 0, nil, err
	}
	return m.kind, m.payload, nil
}

// rlpItemLen returns the encoded length of the first RLP item in b.
func rlpItemLen(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, ErrTooShort
	}
	b0 := b[0]
	switch {
	case b0 <= 0x7f:
		return 1, nil
	case b0 <= 0xb7: // short string
		l := int(b0 - 0x80)
		if len(b) < 1+l {
			return 0, ErrTooShort
		}
		return 1 + l, nil
	case b0 <= 0xbf: // long string
		ll := int(b0 - 0xb7)
		if len(b) < 1+ll {
			return 0, ErrTooShort
		}
		l := 0
		for _, c := range b[1 : 1+ll] {
			l = l<<8 | int(c)
		}
		if len(b) < 1+ll+l {
			return 0, ErrTooShort
		}
		return 1 + ll + l, nil
	case b0 <= 0xf7: // short list
		l := int(b0 - 0xc0)
		if len(b) < 1+l {
			return 0, ErrTooShort
		}
		return 1 + l, nil
	default: // long list
		ll := int(b0 - 0xf7)
		if len(b) < 1+ll {
			return 0, ErrTooShort
		}
		l := 0
		for _, c := range b[1 : 1+ll] {
			l = l<<8 | int(c)
		}
		if len(b) < 1+ll+l {
			return 0, ErrTooShort
		}
		return 1 + ll + l, nil
	}
}
