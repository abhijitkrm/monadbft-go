package exec

import (
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Mock protocol — byte-compatible with monad_consensus_types::block::Mock*.
// Used for conformance tests against Rust fixtures.

var Mock = &Protocol{
	NewProposedHeader:  func() ProposedHeader { return &MockProposedHeader{} },
	NewBody:            func() Body { return &MockBody{} },
	NewFinalizedHeader: func() FinalizedHeader { return &MockFinalizedHeader{} },
}

// MockProposedHeader — Rust struct MockExecutionProposedHeader {} → empty list.
type MockProposedHeader struct{}

func (MockProposedHeader) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte { return p })
}
func (*MockProposedHeader) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	return l.Done()
}

// MockBody — Rust MockExecutionBody { data: Bytes }.
type MockBody struct {
	Data []byte
}

func (b MockBody) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		return rlp.AppendString(p, b.Data)
	})
}
func (b *MockBody) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	data, err := l.Bytes()
	if err != nil {
		return err
	}
	b.Data = append([]byte(nil), data...)
	return l.Done()
}

// MockFinalizedHeader — Rust MockExecutionFinalizedHeader { number: SeqNum }.
type MockFinalizedHeader struct {
	Number types.SeqNum
}

func (h MockFinalizedHeader) SeqNum() types.SeqNum { return h.Number }

func (h MockFinalizedHeader) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		return h.Number.EncodeRLP(p)
	})
}
func (h *MockFinalizedHeader) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	var n types.SeqNum
	if err := n.DecodeRLP(l); err != nil {
		return err
	}
	h.Number = n
	return l.Done()
}
