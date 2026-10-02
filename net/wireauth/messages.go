package wireauth

// Ported from monad-bft/monad-wireauth/src/protocol/messages.rs.
// Wire message layouts — packed, little-endian scalar fields.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	msgTypeHandshakeInitiation = 1
	msgTypeHandshakeResponse   = 2
	msgTypeCookieReply         = 3
	msgTypeData                = 4
)

const timestampSize = 12

const (
	handshakeInitiationSize       = 4 + 4 + publicKeySize + publicKeySize + cipherTagSize + timestampSize + cipherTagSize + macTagSize + macTagSize
	handshakeInitiationMac1Offset = 4 + 4 + publicKeySize + publicKeySize + cipherTagSize + timestampSize + cipherTagSize
	handshakeInitiationMac2Offset = handshakeInitiationMac1Offset + macTagSize

	handshakeResponseSize       = 4 + 4 + 4 + publicKeySize + cipherTagSize + macTagSize + macTagSize
	handshakeResponseMac1Offset = 4 + 4 + 4 + publicKeySize + cipherTagSize
	handshakeResponseMac2Offset = handshakeResponseMac1Offset + macTagSize

	cookieReplySize = 4 + 4 + 16 + 16 + cipherTagSize

	dataPacketHeaderSize = 4 + 4 + 8 + cipherTagSize
)

var errInvalidHeader = errors.New("invalid message header")

// handshakeInitiation — message type 1.
type handshakeInitiation struct {
	senderIndex           uint32
	ephemeralPublic       [publicKeySize]byte
	encryptedStatic       [publicKeySize]byte
	encryptedStaticTag    [cipherTagSize]byte
	encryptedTimestamp    [timestampSize]byte
	encryptedTimestampTag [cipherTagSize]byte
	mac1                  macTag
	mac2                  macTag
}

func (m *handshakeInitiation) marshal() []byte {
	b := make([]byte, handshakeInitiationSize)
	b[0] = msgTypeHandshakeInitiation
	binary.LittleEndian.PutUint32(b[4:], m.senderIndex)
	o := 8
	copy(b[o:], m.ephemeralPublic[:])
	o += publicKeySize
	copy(b[o:], m.encryptedStatic[:])
	o += publicKeySize
	copy(b[o:], m.encryptedStaticTag[:])
	o += cipherTagSize
	copy(b[o:], m.encryptedTimestamp[:])
	o += timestampSize
	copy(b[o:], m.encryptedTimestampTag[:])
	o += cipherTagSize
	copy(b[o:], m.mac1[:])
	o += macTagSize
	copy(b[o:], m.mac2[:])
	return b
}

func parseHandshakeInitiation(b []byte) (*handshakeInitiation, error) {
	if len(b) != handshakeInitiationSize {
		return nil, fmt.Errorf("%w: handshake initiation wants %d bytes, got %d",
			errInvalidHeader, handshakeInitiationSize, len(b))
	}
	if b[0] != msgTypeHandshakeInitiation {
		return nil, errInvalidHeader
	}
	m := &handshakeInitiation{}
	m.senderIndex = binary.LittleEndian.Uint32(b[4:])
	o := 8
	copy(m.ephemeralPublic[:], b[o:])
	o += publicKeySize
	copy(m.encryptedStatic[:], b[o:])
	o += publicKeySize
	copy(m.encryptedStaticTag[:], b[o:])
	o += cipherTagSize
	copy(m.encryptedTimestamp[:], b[o:])
	o += timestampSize
	copy(m.encryptedTimestampTag[:], b[o:])
	o += cipherTagSize
	copy(m.mac1[:], b[o:])
	o += macTagSize
	copy(m.mac2[:], b[o:])
	return m, nil
}

func (m *handshakeInitiation) mac1Input() []byte { return m.marshal()[:handshakeInitiationMac1Offset] }
func (m *handshakeInitiation) mac2Input() []byte { return m.marshal()[:handshakeInitiationMac2Offset] }

// handshakeResponse — message type 2.
type handshakeResponse struct {
	senderIndex         uint32
	receiverIndex       uint32
	ephemeralPublic     [publicKeySize]byte
	encryptedNothingTag [cipherTagSize]byte
	mac1                macTag
	mac2                macTag
}

func (m *handshakeResponse) marshal() []byte {
	b := make([]byte, handshakeResponseSize)
	b[0] = msgTypeHandshakeResponse
	binary.LittleEndian.PutUint32(b[4:], m.senderIndex)
	binary.LittleEndian.PutUint32(b[8:], m.receiverIndex)
	o := 12
	copy(b[o:], m.ephemeralPublic[:])
	o += publicKeySize
	copy(b[o:], m.encryptedNothingTag[:])
	o += cipherTagSize
	copy(b[o:], m.mac1[:])
	o += macTagSize
	copy(b[o:], m.mac2[:])
	return b
}

func parseHandshakeResponse(b []byte) (*handshakeResponse, error) {
	if len(b) != handshakeResponseSize {
		return nil, fmt.Errorf("%w: handshake response wants %d bytes, got %d",
			errInvalidHeader, handshakeResponseSize, len(b))
	}
	if b[0] != msgTypeHandshakeResponse {
		return nil, errInvalidHeader
	}
	m := &handshakeResponse{}
	m.senderIndex = binary.LittleEndian.Uint32(b[4:])
	m.receiverIndex = binary.LittleEndian.Uint32(b[8:])
	o := 12
	copy(m.ephemeralPublic[:], b[o:])
	o += publicKeySize
	copy(m.encryptedNothingTag[:], b[o:])
	o += cipherTagSize
	copy(m.mac1[:], b[o:])
	o += macTagSize
	copy(m.mac2[:], b[o:])
	return m, nil
}

func (m *handshakeResponse) mac1Input() []byte { return m.marshal()[:handshakeResponseMac1Offset] }
func (m *handshakeResponse) mac2Input() []byte { return m.marshal()[:handshakeResponseMac2Offset] }

// cookieReply — message type 3.
type cookieReply struct {
	receiverIndex      uint32
	nonce              cipherNonce
	encryptedCookie    [16]byte
	encryptedCookieTag [cipherTagSize]byte
}

func (m *cookieReply) marshal() []byte {
	b := make([]byte, cookieReplySize)
	b[0] = msgTypeCookieReply
	binary.LittleEndian.PutUint32(b[4:], m.receiverIndex)
	copy(b[8:], m.nonce[:])
	copy(b[24:], m.encryptedCookie[:])
	copy(b[40:], m.encryptedCookieTag[:])
	return b
}

func parseCookieReply(b []byte) (*cookieReply, error) {
	if len(b) != cookieReplySize {
		return nil, fmt.Errorf("%w: cookie reply wants %d bytes, got %d",
			errInvalidHeader, cookieReplySize, len(b))
	}
	if b[0] != msgTypeCookieReply {
		return nil, errInvalidHeader
	}
	m := &cookieReply{}
	m.receiverIndex = binary.LittleEndian.Uint32(b[4:])
	copy(m.nonce[:], b[8:24])
	copy(m.encryptedCookie[:], b[24:40])
	copy(m.encryptedCookieTag[:], b[40:])
	return m, nil
}

// dataPacketHeader — message type 4 header (32 bytes).
type dataPacketHeader struct {
	receiverIndex uint32
	nonce         uint64
	tag           [cipherTagSize]byte
}

func (h *dataPacketHeader) marshal() []byte {
	b := make([]byte, dataPacketHeaderSize)
	b[0] = msgTypeData
	binary.LittleEndian.PutUint32(b[4:], h.receiverIndex)
	binary.LittleEndian.PutUint64(b[8:], h.nonce)
	copy(b[16:], h.tag[:])
	return b
}

func parseDataPacketHeader(b []byte) (*dataPacketHeader, error) {
	if len(b) < dataPacketHeaderSize {
		return nil, fmt.Errorf("%w: data packet header wants %d bytes, got %d",
			errInvalidHeader, dataPacketHeaderSize, len(b))
	}
	if b[0] != msgTypeData {
		return nil, errInvalidHeader
	}
	h := &dataPacketHeader{}
	h.receiverIndex = binary.LittleEndian.Uint32(b[4:])
	h.nonce = binary.LittleEndian.Uint64(b[8:])
	copy(h.tag[:], b[16:32])
	return h, nil
}

// macMessage is implemented by messages carrying mac1/mac2.
type macMessage interface {
	mac1Tag() macTag
	mac2Tag() macTag
	mac1Input() []byte
	mac2Input() []byte
}

func (m *handshakeInitiation) mac1Tag() macTag { return m.mac1 }
func (m *handshakeInitiation) mac2Tag() macTag { return m.mac2 }
func (m *handshakeResponse) mac1Tag() macTag   { return m.mac1 }
func (m *handshakeResponse) mac2Tag() macTag   { return m.mac2 }

// dataPacket is a parsed type-4 datagram. Payload aliases the caller's
// buffer; decryption happens in place.
type dataPacket struct {
	header  dataPacketHeader
	payload []byte
}

func parseDataPacket(b []byte) (dataPacket, error) {
	h, err := parseDataPacketHeader(b)
	if err != nil {
		return dataPacket{}, err
	}
	return dataPacket{header: *h, payload: b[dataPacketHeaderSize:]}, nil
}

// controlKind tags the parsed control packet variant.
type controlKind int

const (
	controlInitiation controlKind = iota
	controlResponse
	controlCookie
	controlKeepalive
)

// controlPacket is a parsed control datagram (Rust ControlPacket).
type controlPacket struct {
	kind       controlKind
	initiation *handshakeInitiation
	response   *handshakeResponse
	cookie     *cookieReply
	keepalive  dataPacket
}

// parsePacket dispatches on the message-type byte. Data packets with an
// empty payload are keepalives (control); non-empty payloads are data.
// Returns (control, data, err) — exactly one of control/data is set on success.
func parsePacket(b []byte) (*controlPacket, *dataPacket, error) {
	if len(b) == 0 {
		return nil, nil, fmt.Errorf("%w: empty packet", errInvalidHeader)
	}
	switch b[0] {
	case msgTypeHandshakeInitiation:
		m, err := parseHandshakeInitiation(b)
		if err != nil {
			return nil, nil, err
		}
		return &controlPacket{kind: controlInitiation, initiation: m}, nil, nil
	case msgTypeHandshakeResponse:
		m, err := parseHandshakeResponse(b)
		if err != nil {
			return nil, nil, err
		}
		return &controlPacket{kind: controlResponse, response: m}, nil, nil
	case msgTypeCookieReply:
		m, err := parseCookieReply(b)
		if err != nil {
			return nil, nil, err
		}
		return &controlPacket{kind: controlCookie, cookie: m}, nil, nil
	case msgTypeData:
		p, err := parseDataPacket(b)
		if err != nil {
			return nil, nil, err
		}
		if len(p.payload) == 0 {
			return &controlPacket{kind: controlKeepalive, keepalive: p}, nil, nil
		}
		return nil, &p, nil
	default:
		return nil, nil, errInvalidHeader
	}
}
