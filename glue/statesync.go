package glue

import (
	"github.com/abhijitkrm/monadbft-go/rlp"
)

const statesyncNetworkMessageName = "StateSyncNetworkMessage"

// StateSyncRequest — Rust StateSyncRequest. Decode is version-gated: if the
// version is incompatible the remaining payload is skipped (zeros).
type StateSyncRequest struct {
	Version     StateSyncVersion
	Prefix      uint64
	PrefixBytes uint8
	Target      uint64
	From        uint64
	Until       uint64
	OldTarget   uint64
}

func (r StateSyncRequest) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = r.Version.EncodeRLP(p)
		p = rlp.AppendUint64(p, r.Prefix)
		p = rlp.AppendUint8(p, r.PrefixBytes)
		p = rlp.AppendUint64(p, r.Target)
		p = rlp.AppendUint64(p, r.From)
		p = rlp.AppendUint64(p, r.Until)
		p = rlp.AppendUint64(p, r.OldTarget)
		return p
	})
}

func (r *StateSyncRequest) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := r.Version.DecodeRLP(l); err != nil {
		return err
	}
	if r.Version.IsCompatible() {
		if r.Prefix, err = l.Uint64(); err != nil {
			return err
		}
		pb, err := l.Uint64()
		if err != nil {
			return err
		}
		r.PrefixBytes = uint8(pb)
		if r.Target, err = l.Uint64(); err != nil {
			return err
		}
		if r.From, err = l.Uint64(); err != nil {
			return err
		}
		if r.Until, err = l.Uint64(); err != nil {
			return err
		}
		if r.OldTarget, err = l.Uint64(); err != nil {
			return err
		}
	}
	return l.Done()
}

// UpsertType — Rust StateSyncUpsertType, encodes as [tag].
type UpsertType uint8

const (
	UpsertCode          UpsertType = 1
	UpsertAccount       UpsertType = 2
	UpsertStorage       UpsertType = 3
	UpsertAccountDelete UpsertType = 4
	UpsertStorageDelete UpsertType = 5
	UpsertHeader        UpsertType = 6
)

func (t UpsertType) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		return rlp.AppendUint8(p, uint8(t))
	})
}

func (t *UpsertType) DecodeRLP(s *rlp.Stream) error {
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
	if v < 1 || v > 6 {
		return rlp.ErrCustom
	}
	*t = UpsertType(v)
	return nil
}

// Upsert — Rust StateSyncUpsertV1 { upsert_type, data }.
type Upsert struct {
	Type UpsertType
	Data []byte
}

func (u Upsert) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = u.Type.EncodeRLP(p)
		p = rlp.AppendString(p, u.Data)
		return p
	})
}

func (u *Upsert) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := u.Type.DecodeRLP(l); err != nil {
		return err
	}
	u.Data, err = l.Bytes()
	if err != nil {
		return err
	}
	return l.Done()
}

// BadVersion — Rust StateSyncBadVersion { min_version, max_version }.
type BadVersion struct {
	MinVersion StateSyncVersion
	MaxVersion StateSyncVersion
}

func (b BadVersion) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = b.MinVersion.EncodeRLP(p)
		p = b.MaxVersion.EncodeRLP(p)
		return p
	})
}

func (b *BadVersion) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := b.MinVersion.DecodeRLP(l); err != nil {
		return err
	}
	if err := b.MaxVersion.DecodeRLP(l); err != nil {
		return err
	}
	return l.Done()
}

// StateSyncResponse — Rust StateSyncResponse { version, nonce,
// response_index, request, response[], response_n }.
type StateSyncResponse struct {
	Version       StateSyncVersion
	Nonce         uint64
	ResponseIndex uint32
	Request       StateSyncRequest
	Response      []Upsert
	ResponseN     uint64
}

func (r StateSyncResponse) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = r.Version.EncodeRLP(p)
		p = rlp.AppendUint64(p, r.Nonce)
		p = rlp.AppendUint32(p, r.ResponseIndex)
		p = r.Request.EncodeRLP(p)
		p = rlp.AppendList(p, func(q []byte) []byte {
			for i := range r.Response {
				q = r.Response[i].EncodeRLP(q)
			}
			return q
		})
		p = rlp.AppendUint64(p, r.ResponseN)
		return p
	})
}

func (r *StateSyncResponse) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := r.Version.DecodeRLP(l); err != nil {
		return err
	}
	if r.Nonce, err = l.Uint64(); err != nil {
		return err
	}
	ri, err := l.Uint64()
	if err != nil {
		return err
	}
	r.ResponseIndex = uint32(ri)
	if err := r.Request.DecodeRLP(l); err != nil {
		return err
	}
	ll, err := l.List()
	if err != nil {
		return err
	}
	var ups []Upsert
	for ll.Remaining() > 0 {
		var u Upsert
		if err := u.DecodeRLP(ll); err != nil {
			return err
		}
		ups = append(ups, u)
	}
	if err := ll.Done(); err != nil {
		return err
	}
	if len(ups) > MaxUpsertsPerResponse {
		return rlp.ErrCustom
	}
	r.Response = ups
	if r.ResponseN, err = l.Uint64(); err != nil {
		return err
	}
	return l.Done()
}

// SessionId — Rust SessionId(u64): a 1-tuple struct encodes as [u64].
type SessionId uint64

func (s SessionId) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		return rlp.AppendUint64(p, uint64(s))
	})
}

func (s *SessionId) DecodeRLP(st *rlp.Stream) error {
	l, err := st.List()
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
	*s = SessionId(v)
	return nil
}

// StateSyncNetworkMessage — Rust enum, self-describing [name, tag, payload]:
//
//	1 Request, 2 Response, 3 BadVersion, 4 Completion, 5 NotWhitelisted.
type StateSyncNetworkMessage struct {
	Kind       uint8
	Request    StateSyncRequest
	Response   StateSyncResponse
	BadVersion BadVersion
	Completion SessionId
}

const (
	SSNRequest        = 1
	SSNResponse       = 2
	SSNBadVersion     = 3
	SSNCompletion     = 4
	SSNNotWhitelisted = 5
)

func (m StateSyncNetworkMessage) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = rlp.AppendString(p, []byte(statesyncNetworkMessageName))
		p = rlp.AppendUint8(p, m.Kind)
		switch m.Kind {
		case SSNRequest:
			p = m.Request.EncodeRLP(p)
		case SSNResponse:
			p = m.Response.EncodeRLP(p)
		case SSNBadVersion:
			p = m.BadVersion.EncodeRLP(p)
		case SSNCompletion:
			p = m.Completion.EncodeRLP(p)
		case SSNNotWhitelisted:
		}
		return p
	})
}

func (m *StateSyncNetworkMessage) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	name, err := l.Bytes()
	if err != nil {
		return err
	}
	if string(name) != statesyncNetworkMessageName {
		return rlp.ErrCustom
	}
	tag, err := l.Uint64()
	if err != nil {
		return err
	}
	m.Kind = uint8(tag)
	switch tag {
	case SSNRequest:
		err = m.Request.DecodeRLP(l)
	case SSNResponse:
		err = m.Response.DecodeRLP(l)
	case SSNBadVersion:
		err = m.BadVersion.DecodeRLP(l)
	case SSNCompletion:
		err = m.Completion.DecodeRLP(l)
	case SSNNotWhitelisted:
		err = nil
	default:
		return rlp.ErrCustom
	}
	if err != nil {
		return err
	}
	return l.Done()
}
