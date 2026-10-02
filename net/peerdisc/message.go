package peerdisc

// Ported from monad-peer-discovery/src/message.rs.
// Envelope: [version u16, kind u8, body] — RLP list. Kinds 1..6.

import (
	"errors"

	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

const peerDiscoveryVersion uint16 = 1
const maxPeersInResponse = 16

// Ping — [id u32, local_name_record].
type Ping struct {
	ID              uint32
	LocalNameRecord MonadNameRecord
}

func (p Ping) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(b []byte) []byte {
		b = rlp.AppendUint32(b, p.ID)
		return p.LocalNameRecord.EncodeRLP(b)
	})
}

func (p *Ping) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if p.ID, err = l.Uint32(); err != nil {
		return err
	}
	if err := p.LocalNameRecord.DecodeRLP(l); err != nil {
		return err
	}
	return l.Done()
}

// Pong — [ping_id u32, local_record_seq u64].
type Pong struct {
	PingID         uint32
	LocalRecordSeq uint64
}

func (p Pong) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(b []byte) []byte {
		b = rlp.AppendUint32(b, p.PingID)
		return rlp.AppendUint64(b, p.LocalRecordSeq)
	})
}

func (p *Pong) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if p.PingID, err = l.Uint32(); err != nil {
		return err
	}
	if p.LocalRecordSeq, err = l.Uint64(); err != nil {
		return err
	}
	return l.Done()
}

// PeerLookupRequest — [lookup_id u32, target NodeId, open_discovery bool].
type PeerLookupRequest struct {
	LookupID      uint32
	Target        types.NodeId
	OpenDiscovery bool
}

func (r PeerLookupRequest) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(b []byte) []byte {
		b = rlp.AppendUint32(b, r.LookupID)
		b = r.Target.EncodeRLP(b)
		return rlp.AppendBool(b, r.OpenDiscovery)
	})
}

func (r *PeerLookupRequest) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if r.LookupID, err = l.Uint32(); err != nil {
		return err
	}
	if err := r.Target.DecodeRLP(l); err != nil {
		return err
	}
	if r.OpenDiscovery, err = l.Bool(); err != nil {
		return err
	}
	return l.Done()
}

// PeerLookupResponse — [lookup_id, target, name_records list≤16].
type PeerLookupResponse struct {
	LookupID    uint32
	Target      types.NodeId
	NameRecords []MonadNameRecord
}

func (r PeerLookupResponse) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(b []byte) []byte {
		b = rlp.AppendUint32(b, r.LookupID)
		b = r.Target.EncodeRLP(b)
		return rlp.AppendList(b, func(b2 []byte) []byte {
			for _, nr := range r.NameRecords {
				b2 = nr.EncodeRLP(b2)
			}
			return b2
		})
	})
}

func (r *PeerLookupResponse) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if r.LookupID, err = l.Uint32(); err != nil {
		return err
	}
	if err := r.Target.DecodeRLP(l); err != nil {
		return err
	}
	records, err := l.List()
	if err != nil {
		return err
	}
	for records.Remaining() > 0 {
		var nr MonadNameRecord
		if err := nr.DecodeRLP(records); err != nil {
			return err
		}
		r.NameRecords = append(r.NameRecords, nr)
	}
	if len(r.NameRecords) > maxPeersInResponse {
		return errors.New("peerdisc: too many peers in lookup response")
	}
	return l.Done()
}

// PeerDiscoveryMessage — tagged envelope (Rust enum).
type PeerDiscoveryMessage struct {
	Kind           uint8 // 1..6
	Ping           *Ping
	Pong           *Pong
	LookupRequest  *PeerLookupRequest
	LookupResponse *PeerLookupResponse
	// kinds 5/6 carry no body
}

const (
	msgKindPing uint8 = iota + 1
	msgKindPong
	msgKindPeerLookupRequest
	msgKindPeerLookupResponse
	msgKindFullNodeRaptorcastRequest
	msgKindFullNodeRaptorcastResponse
)

func PingMessage(p Ping) PeerDiscoveryMessage {
	return PeerDiscoveryMessage{Kind: msgKindPing, Ping: &p}
}
func PongMessage(p Pong) PeerDiscoveryMessage {
	return PeerDiscoveryMessage{Kind: msgKindPong, Pong: &p}
}
func PeerLookupRequestMessage(r PeerLookupRequest) PeerDiscoveryMessage {
	return PeerDiscoveryMessage{Kind: msgKindPeerLookupRequest, LookupRequest: &r}
}
func PeerLookupResponseMessage(r PeerLookupResponse) PeerDiscoveryMessage {
	return PeerDiscoveryMessage{Kind: msgKindPeerLookupResponse, LookupResponse: &r}
}

var (
	FullNodeRaptorcastRequestMessage  = PeerDiscoveryMessage{Kind: msgKindFullNodeRaptorcastRequest}
	FullNodeRaptorcastResponseMessage = PeerDiscoveryMessage{Kind: msgKindFullNodeRaptorcastResponse}
)

func (m PeerDiscoveryMessage) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(b []byte) []byte {
		b = rlp.AppendUint16(b, peerDiscoveryVersion)
		b = rlp.AppendUint8(b, m.Kind)
		switch m.Kind {
		case msgKindPing:
			b = m.Ping.EncodeRLP(b)
		case msgKindPong:
			b = m.Pong.EncodeRLP(b)
		case msgKindPeerLookupRequest:
			b = m.LookupRequest.EncodeRLP(b)
		case msgKindPeerLookupResponse:
			b = m.LookupResponse.EncodeRLP(b)
		case msgKindFullNodeRaptorcastRequest, msgKindFullNodeRaptorcastResponse:
		default:
			panic("peerdisc: unknown message kind")
		}
		return b
	})
}

func (m *PeerDiscoveryMessage) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if _, err := l.Uint16(); err != nil { // version (checked upstream too — ignored)
		return err
	}
	kind, err := l.Uint8()
	if err != nil {
		return err
	}
	m.Kind = kind
	switch kind {
	case msgKindPing:
		m.Ping = &Ping{}
		err = m.Ping.DecodeRLP(l)
	case msgKindPong:
		m.Pong = &Pong{}
		err = m.Pong.DecodeRLP(l)
	case msgKindPeerLookupRequest:
		m.LookupRequest = &PeerLookupRequest{}
		err = m.LookupRequest.DecodeRLP(l)
	case msgKindPeerLookupResponse:
		m.LookupResponse = &PeerLookupResponse{}
		err = m.LookupResponse.DecodeRLP(l)
	case msgKindFullNodeRaptorcastRequest, msgKindFullNodeRaptorcastResponse:
	default:
		return errors.New("peerdisc: unknown PeerDiscoveryMessage kind")
	}
	if err != nil {
		return err
	}
	return l.Done()
}
