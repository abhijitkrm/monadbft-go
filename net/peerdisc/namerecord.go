package peerdisc

// Ported from monad-bft/monad-peer-discovery/src/lib.rs — Port/PortList,
// NameRecord, MonadNameRecord (RLP-layout-identical, secp256k1-signed under
// the "monad/name-record/1" domain).

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

type PortTag uint8

const (
	PortTagTCP              PortTag = 0
	PortTagUDP              PortTag = 1
	PortTagAuthenticatedUDP PortTag = 2
	PortTagDirectUDP        PortTag = 3
	PortTagEncryptedTCP     PortTag = 4
)

const maxPorts = 8

// Port — Rust { tag: u8, port: NonZeroU16 }.
type Port struct {
	Tag  uint8
	Port uint16
}

func NewPort(tag PortTag, port uint16) Port {
	if port == 0 {
		panic("name record port must be non-zero")
	}
	return Port{Tag: uint8(tag), Port: port}
}

func (p Port) TagEnum() (PortTag, bool) {
	t := PortTag(p.Tag)
	switch t {
	case PortTagTCP, PortTagUDP, PortTagAuthenticatedUDP, PortTagDirectUDP, PortTagEncryptedTCP:
		return t, true
	}
	return 0, false
}

func (p Port) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(b []byte) []byte {
		b = rlp.AppendUint8(b, p.Tag)
		return rlp.AppendUint16(b, p.Port)
	})
}

func (p *Port) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	tag, err := l.Uint8()
	if err != nil {
		return err
	}
	port, err := l.Uint16()
	if err != nil {
		return err
	}
	if err := l.Done(); err != nil {
		return err
	}
	if port == 0 {
		return errors.New("peerdisc: invalid zero port")
	}
	p.Tag, p.Port = tag, port
	return nil
}

// NameRecord — Rust NameRecord { ip: Ipv4Addr, ports: PortList<8>,
// capabilities: u64, seq: u64 }.
type NameRecord struct {
	IP           netip.Addr // must be Is4()
	Ports        []Port
	Capabilities uint64
	Seq          uint64
}

func (n *NameRecord) validate() error {
	if !n.IP.Is4() {
		return errors.New("peerdisc: name record ip must be IPv4")
	}
	seen := map[uint8]bool{}
	for _, p := range n.Ports {
		if seen[p.Tag] {
			return errors.New("peerdisc: duplicate port tag")
		}
		seen[p.Tag] = true
	}
	if len(n.Ports) > maxPorts {
		return errors.New("peerdisc: too many ports")
	}
	if n.portByTag(PortTagTCP) == 0 {
		return errors.New("peerdisc: missing TCP port")
	}
	if n.portByTag(PortTagAuthenticatedUDP) == 0 {
		return errors.New("peerdisc: missing Authenticated UDP port")
	}
	return nil
}

func (n *NameRecord) portByTag(tag PortTag) uint16 {
	for _, p := range n.Ports {
		if t, _ := p.TagEnum(); t == tag {
			return p.Port
		}
	}
	return 0
}

func (n *NameRecord) TCPPort() uint16 { return n.portByTag(PortTagTCP) }
func (n *NameRecord) UDPPort() uint16 { return n.portByTag(PortTagUDP) }
func (n *NameRecord) AuthUDPPort() uint16 {
	return n.portByTag(PortTagAuthenticatedUDP)
}
func (n *NameRecord) DirectUDPPort() uint16    { return n.portByTag(PortTagDirectUDP) }
func (n *NameRecord) EncryptedTCPPort() uint16 { return n.portByTag(PortTagEncryptedTCP) }

func (n *NameRecord) TCPSocket() netip.AddrPort {
	return netip.AddrPortFrom(n.IP, n.TCPPort())
}
func (n *NameRecord) UDPSocket() (netip.AddrPort, bool) {
	if p := n.UDPPort(); p != 0 {
		return netip.AddrPortFrom(n.IP, p), true
	}
	return netip.AddrPort{}, false
}
func (n *NameRecord) AuthUDPSocket() netip.AddrPort {
	return netip.AddrPortFrom(n.IP, n.AuthUDPPort())
}
func (n *NameRecord) DirectUDPSocket() (netip.AddrPort, bool) {
	if p := n.DirectUDPPort(); p != 0 {
		return netip.AddrPortFrom(n.IP, p), true
	}
	return netip.AddrPort{}, false
}

// AllUDPSockets — Rust all_udp_sockets(): udp + authenticated + direct.
func (n *NameRecord) AllUDPSockets() []netip.AddrPort {
	out := []netip.AddrPort{n.AuthUDPSocket()}
	if s, ok := n.UDPSocket(); ok {
		out = append([]netip.AddrPort{s}, out...)
	}
	if s, ok := n.DirectUDPSocket(); ok {
		out = append(out, s)
	}
	return out
}

// NewNameRecord — Rust NameRecord::new (tcp + optional udp + auth udp).
func NewNameRecord(ip netip.Addr, tcpPort uint16, udpPort, authUDPPort uint16, capabilities, seq uint64) NameRecord {
	ports := []Port{NewPort(PortTagTCP, tcpPort)}
	if udpPort != 0 {
		ports = append(ports, NewPort(PortTagUDP, udpPort))
	}
	ports = append(ports, NewPort(PortTagAuthenticatedUDP, authUDPPort))
	return NameRecord{IP: ip, Ports: ports, Capabilities: capabilities, Seq: seq}
}

// NewNameRecordWithPorts — Rust NameRecord::new_with_ports.
func NewNameRecordWithPorts(ip netip.Addr, tcp, udp, authUDP, directUDP, encTCP uint16, seq uint64) NameRecord {
	ports := []Port{NewPort(PortTagTCP, tcp)}
	if udp != 0 {
		ports = append(ports, NewPort(PortTagUDP, udp))
	}
	ports = append(ports, NewPort(PortTagAuthenticatedUDP, authUDP))
	if directUDP != 0 {
		ports = append(ports, NewPort(PortTagDirectUDP, directUDP))
	}
	if encTCP != 0 {
		ports = append(ports, NewPort(PortTagEncryptedTCP, encTCP))
	}
	return NameRecord{IP: ip, Ports: ports, Seq: seq}
}

func (n NameRecord) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(b []byte) []byte {
		ip4 := n.IP.As4()
		b = rlp.AppendString(b, ip4[:])
		b = rlp.AppendList(b, func(b2 []byte) []byte {
			for _, p := range n.Ports {
				b2 = p.EncodeRLP(b2)
			}
			return b2
		})
		b = rlp.AppendUint64(b, n.Capabilities)
		return rlp.AppendUint64(b, n.Seq)
	})
}

func (n *NameRecord) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	ipb, err := l.FixedBytes(4)
	if err != nil {
		return fmt.Errorf("peerdisc: invalid IPv4 address: %w", err)
	}
	var nr NameRecord
	nr.IP = netip.AddrFrom4([4]byte(ipb))
	portsList, err := l.List()
	if err != nil {
		return err
	}
	for portsList.Remaining() > 0 {
		var p Port
		if err := p.DecodeRLP(portsList); err != nil {
			return err
		}
		nr.Ports = append(nr.Ports, p)
	}
	if nr.Capabilities, err = l.Uint64(); err != nil {
		return err
	}
	if nr.Seq, err = l.Uint64(); err != nil {
		return err
	}
	if err := l.Done(); err != nil {
		return err
	}
	if err := nr.validate(); err != nil {
		return err
	}
	*n = nr
	return nil
}

// MonadNameRecord — signed name record (secp256k1 recoverable signature).
type MonadNameRecord struct {
	NameRecord NameRecord
	Signature  crypto.SecpSignature
}

func NewMonadNameRecord(nr NameRecord, key *crypto.SecpKeyPair) MonadNameRecord {
	return MonadNameRecord{
		NameRecord: nr,
		Signature:  key.Sign(crypto.DomainNameRecord, rlp.Encode(nr)),
	}
}

// RecoverPubKey recovers the signer NodeId (Rust recover_pubkey).
func (m MonadNameRecord) RecoverPubKey() (types.NodeId, error) {
	pk, err := m.Signature.RecoverPubKey(crypto.DomainNameRecord, rlp.Encode(m.NameRecord))
	if err != nil {
		return types.NodeId{}, err
	}
	return types.NewNodeId(pk), nil
}

func (m MonadNameRecord) Seq() uint64 { return m.NameRecord.Seq }

func (m MonadNameRecord) Equal(o MonadNameRecord) bool {
	if m.Signature != o.Signature || m.NameRecord.Seq != o.NameRecord.Seq ||
		m.NameRecord.Capabilities != o.NameRecord.Capabilities ||
		m.NameRecord.IP != o.NameRecord.IP ||
		len(m.NameRecord.Ports) != len(o.NameRecord.Ports) {
		return false
	}
	for i, p := range m.NameRecord.Ports {
		if p != o.NameRecord.Ports[i] {
			return false
		}
	}
	return true
}

func (m MonadNameRecord) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(b []byte) []byte {
		b = m.NameRecord.EncodeRLP(b)
		sig := m.Signature.Serialize()
		return rlp.AppendString(b, sig)
	})
}

func (m *MonadNameRecord) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := m.NameRecord.DecodeRLP(l); err != nil {
		return err
	}
	sigB, err := l.FixedBytes(crypto.SecpSignatureSize)
	if err != nil {
		return err
	}
	sig, err := crypto.SecpSignatureFromBytes(sigB)
	if err != nil {
		return err
	}
	m.Signature = sig
	return l.Done()
}

func (m MonadNameRecord) UDPSocket() (netip.AddrPort, bool) {
	return m.NameRecord.UDPSocket()
}
func (m MonadNameRecord) AuthUDPSocket() netip.AddrPort {
	return m.NameRecord.AuthUDPSocket()
}
func (m MonadNameRecord) TCPSocket() netip.AddrPort { return m.NameRecord.TCPSocket() }
func (m MonadNameRecord) AllUDPSockets() []netip.AddrPort {
	return m.NameRecord.AllUDPSockets()
}
