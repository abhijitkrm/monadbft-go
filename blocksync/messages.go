// Package blocksync ports monad-blocksync: the request/response protocol for
// fetching missing block headers and payloads from peers.
//
// This file holds the wire message types; all encodings are byte-identical to
// the Rust impl (self-describing RLP: [name, tag, fields...]).
package blocksync

import (
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/rlp"
)

// MaxNumHeaders — Rust BLOCKSYNC_MAX_NUM_HEADERS: bounds RLP deserialization.
const MaxNumHeaders = 800

const (
	requestMessageName  = "BlockSyncRequestMessage"
	responseMessageName = "BlockSyncResponseMessage"
	headersResponseName = "BlockSyncHeadersResponse"
	bodyResponseName    = "BlockSyncBodyResponse"
)

// RequestMessage — Rust BlockSyncRequestMessage: Headers(range) | Payload(id).
type RequestMessage struct {
	IsPayload bool
	Range     cstypes.BlockRange           // Headers
	PayloadID cstypes.ConsensusBlockBodyId // Payload
}

func RequestHeaders(r cstypes.BlockRange) RequestMessage {
	return RequestMessage{Range: r}
}
func RequestPayload(id cstypes.ConsensusBlockBodyId) RequestMessage {
	return RequestMessage{IsPayload: true, PayloadID: id}
}

func (m RequestMessage) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = rlp.AppendString(p, []byte(requestMessageName))
		if m.IsPayload {
			p = rlp.AppendUint8(p, 2)
			p = m.PayloadID.EncodeRLP(p)
		} else {
			p = rlp.AppendUint8(p, 1)
			p = m.Range.EncodeRLP(p)
		}
		return p
	})
}

func (m *RequestMessage) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	name, err := l.Bytes()
	if err != nil {
		return err
	}
	if string(name) != requestMessageName {
		return rlp.ErrCustom
	}
	tag, err := l.Uint64()
	if err != nil {
		return err
	}
	switch tag {
	case 1:
		err = m.Range.DecodeRLP(l)
	case 2:
		m.IsPayload = true
		err = m.PayloadID.DecodeRLP(l)
	default:
		return rlp.ErrCustom
	}
	if err != nil {
		return err
	}
	return l.Done()
}

// HeadersResponse — Rust BlockSyncHeadersResponse:
// Found(range, headers) | NotAvailable(range).
type HeadersResponse struct {
	Found   bool
	Range   cstypes.BlockRange
	Headers []cstypes.ConsensusBlockHeader // Found only
}

func (r HeadersResponse) GetBlockRange() cstypes.BlockRange { return r.Range }

func (r HeadersResponse) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = rlp.AppendString(p, []byte(headersResponseName))
		if r.Found {
			p = rlp.AppendUint8(p, 1)
			p = r.Range.EncodeRLP(p)
			p = rlp.AppendList(p, func(q []byte) []byte {
				for i := range r.Headers {
					q = r.Headers[i].EncodeRLP(q)
				}
				return q
			})
		} else {
			p = rlp.AppendUint8(p, 2)
			p = r.Range.EncodeRLP(p)
		}
		return p
	})
}

func (r *HeadersResponse) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	name, err := l.Bytes()
	if err != nil {
		return err
	}
	if string(name) != headersResponseName {
		return rlp.ErrCustom
	}
	tag, err := l.Uint64()
	if err != nil {
		return err
	}
	switch tag {
	case 1:
		r.Found = true
		if err = r.Range.DecodeRLP(l); err != nil {
			return err
		}
		ll, err := l.List()
		if err != nil {
			return err
		}
		var hdrs []cstypes.ConsensusBlockHeader
		for ll.Remaining() > 0 {
			var h cstypes.ConsensusBlockHeader
			if err := h.DecodeRLP(ll, ep); err != nil {
				return err
			}
			hdrs = append(hdrs, h)
		}
		if err := ll.Done(); err != nil {
			return err
		}
		if len(hdrs) > MaxNumHeaders {
			return rlp.ErrCustom
		}
		r.Headers = hdrs
	case 2:
		err = r.Range.DecodeRLP(l)
	default:
		return rlp.ErrCustom
	}
	if err != nil {
		return err
	}
	return l.Done()
}

// BodyResponse — Rust BlockSyncBodyResponse: Found(body) | NotAvailable(id).
type BodyResponse struct {
	Found bool
	Body  cstypes.ConsensusBlockBody   // Found only
	ID    cstypes.ConsensusBlockBodyId // NotAvailable only
}

func (r BodyResponse) GetPayloadID() cstypes.ConsensusBlockBodyId {
	if r.Found {
		return r.Body.GetId()
	}
	return r.ID
}

func (r BodyResponse) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = rlp.AppendString(p, []byte(bodyResponseName))
		if r.Found {
			p = rlp.AppendUint8(p, 1)
			p = r.Body.EncodeRLP(p)
		} else {
			p = rlp.AppendUint8(p, 2)
			p = r.ID.EncodeRLP(p)
		}
		return p
	})
}

func (r *BodyResponse) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	name, err := l.Bytes()
	if err != nil {
		return err
	}
	if string(name) != bodyResponseName {
		return rlp.ErrCustom
	}
	tag, err := l.Uint64()
	if err != nil {
		return err
	}
	switch tag {
	case 1:
		r.Found = true
		err = r.Body.DecodeRLP(l, ep)
	case 2:
		err = r.ID.DecodeRLP(l)
	default:
		return rlp.ErrCustom
	}
	if err != nil {
		return err
	}
	return l.Done()
}

// ResponseMessage — Rust BlockSyncResponseMessage:
// HeadersResponse | PayloadResponse.
type ResponseMessage struct {
	IsPayload bool
	Headers   HeadersResponse // IsPayload=false
	Body      BodyResponse    // IsPayload=true
}

func ResponseHeaders(r cstypes.BlockRange, headers []cstypes.ConsensusBlockHeader) ResponseMessage {
	return ResponseMessage{Headers: HeadersResponse{Found: true, Range: r, Headers: headers}}
}
func ResponseHeadersNotAvailable(r cstypes.BlockRange) ResponseMessage {
	return ResponseMessage{Headers: HeadersResponse{Found: false, Range: r}}
}
func ResponsePayload(b cstypes.ConsensusBlockBody) ResponseMessage {
	return ResponseMessage{IsPayload: true, Body: BodyResponse{Found: true, Body: b}}
}
func ResponsePayloadNotAvailable(id cstypes.ConsensusBlockBodyId) ResponseMessage {
	return ResponseMessage{IsPayload: true, Body: BodyResponse{Found: false, ID: id}}
}

func (m ResponseMessage) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = rlp.AppendString(p, []byte(responseMessageName))
		if m.IsPayload {
			p = rlp.AppendUint8(p, 2)
			p = m.Body.EncodeRLP(p)
		} else {
			p = rlp.AppendUint8(p, 1)
			p = m.Headers.EncodeRLP(p)
		}
		return p
	})
}

func (m *ResponseMessage) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	name, err := l.Bytes()
	if err != nil {
		return err
	}
	if string(name) != responseMessageName {
		return rlp.ErrCustom
	}
	tag, err := l.Uint64()
	if err != nil {
		return err
	}
	switch tag {
	case 1:
		err = m.Headers.DecodeRLP(l, ep)
	case 2:
		m.IsPayload = true
		err = m.Body.DecodeRLP(l, ep)
	default:
		return rlp.ErrCustom
	}
	if err != nil {
		return err
	}
	return l.Done()
}

// SelfRequester — Rust BlockSyncSelfRequester: Consensus(1) | StateSync(2).
type SelfRequester uint8

const (
	SelfRequesterConsensus SelfRequester = 1
	SelfRequesterStateSync SelfRequester = 2
)

// SelfRequester encodes as a 1-element list [tag], matching Rust
// encode_list of a single u8 discriminant.
func (r SelfRequester) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		return rlp.AppendUint8(p, uint8(r))
	})
}

func (r *SelfRequester) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	v, err := l.Uint64()
	if err != nil {
		return err
	}
	if err := l.Done(); err != nil {
		return err
	}
	if v != 1 && v != 2 {
		return rlp.ErrCustom
	}
	*r = SelfRequester(v)
	return nil
}
