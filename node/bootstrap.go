package node

// Bootstrap peers file — the Go analogue of upstream monad-node-config's
// NodeBootstrapConfig/NodeBootstrapPeerConfig. Upstream serializes as TOML
// ([[peers]] entries); this port uses JSON — the file is node-local config,
// not a wire format. Each entry is a decomposed self-signed name record that
// converts to a glue.PeerEntry and verifies as a peerdisc.MonadNameRecord,
// exactly like upstream's bootstrap_peer_entry + MonadNameRecord::try_from.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/net/peerdisc"
	"github.com/abhijitkrm/monadbft-go/types"
)

// BootstrapPeerConfig — one [[peers]] entry (upstream field names).
type BootstrapPeerConfig struct {
	// Address is the peer's advertised IPv4 — "ip" (with tcp_port/udp_port
	// fields) or "ip:port" (port fills both tcp and udp unless overridden).
	// A DNS name resolving to A is also accepted (upstream resolve_domain_v4).
	Address          string `json:"address"`
	TCPPort          uint16 `json:"tcp_port,omitempty"`
	UDPPort          uint16 `json:"udp_port,omitempty"`
	RecordSeqNum     uint64 `json:"record_seq_num"`
	Secp256k1Pubkey  string `json:"secp256k1_pubkey"` // hex, 33-byte compressed
	NameRecordSig    string `json:"name_record_sig"`  // hex, 65-byte recoverable
	AuthPort         uint16 `json:"auth_port"`        // required non-zero
	DirectUDPPort    uint16 `json:"direct_udp_port,omitempty"`
	EncryptedTCPPort uint16 `json:"encrypted_tcp_port,omitempty"`
}

// parseAddressFields — Rust parse_address_fields: split host/tcp/udp port
// resolution. Returns (host, tcpPort, udpPort).
func parseAddressFields(address string, tcpPort, udpPort uint16) (string, uint16, uint16, error) {
	if tcpPort != 0 {
		if strings.Contains(address, ":") {
			return "", 0, 0, errors.New("split bootstrap peer address must not include a port")
		}
		if address == "" {
			return "", 0, 0, errors.New("bootstrap peer address host must not be empty")
		}
		return address, tcpPort, udpPort, nil
	}
	if udpPort != 0 {
		return "", 0, 0, errors.New("bootstrap peer udp_port requires tcp_port")
	}
	i := strings.LastIndexByte(address, ':')
	if i < 0 {
		return "", 0, 0, errors.New("bootstrap peer address must include a port")
	}
	host, port := address[:i], address[i+1:]
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", 0, 0, errors.New("bootstrap peer address port must be non-zero")
	}
	if host == "" {
		return "", 0, 0, errors.New("bootstrap peer address host must not be empty")
	}
	return host, uint16(p), uint16(p), nil
}

// resolveV4 — host → IPv4 (upstream resolve_domain_v4: literal IP or DNS A).
func resolveV4(host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			return ip, nil
		}
		return netip.Addr{}, fmt.Errorf("bootstrap peer address %q is not IPv4", host)
	}
	ips, err := net.DefaultResolver.LookupIP(nil, "ip4", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve %q: %w", host, err)
	}
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok && a.Is4() {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("resolve %q: no IPv4 answer", host)
}

// PeerEntry — convert to a transport PeerEntry (signature not yet verified).
func (p BootstrapPeerConfig) PeerEntry() (glue.PeerEntry, error) {
	host, tcpPort, udpPort, err := parseAddressFields(p.Address, p.TCPPort, p.UDPPort)
	if err != nil {
		return glue.PeerEntry{}, err
	}
	ip, err := resolveV4(host)
	if err != nil {
		return glue.PeerEntry{}, err
	}
	pubBytes, err := hex.DecodeString(strings.TrimPrefix(p.Secp256k1Pubkey, "0x"))
	if err != nil {
		return glue.PeerEntry{}, fmt.Errorf("secp256k1_pubkey: %w", err)
	}
	pub, err := crypto.SecpPubKeyFromBytes(pubBytes)
	if err != nil {
		return glue.PeerEntry{}, fmt.Errorf("secp256k1_pubkey: %w", err)
	}
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(p.NameRecordSig, "0x"))
	if err != nil {
		return glue.PeerEntry{}, fmt.Errorf("name_record_sig: %w", err)
	}
	sig, err := crypto.SecpSignatureFromBytes(sigBytes)
	if err != nil {
		return glue.PeerEntry{}, fmt.Errorf("name_record_sig: %w", err)
	}
	if p.AuthPort == 0 {
		return glue.PeerEntry{}, errors.New("bootstrap peer auth_port must be non-zero")
	}
	return glue.PeerEntry{
		Pubkey:           types.NewNodeId(pub),
		Addr:             ip,
		TCPPort:          tcpPort,
		UDPPort:          udpPort,
		Signature:        sig,
		RecordSeqNum:     p.RecordSeqNum,
		AuthPort:         p.AuthPort,
		DirectUDPPort:    p.DirectUDPPort,
		EncryptedTCPPort: p.EncryptedTCPPort,
	}, nil
}

// NameRecord — verify the self-signature and produce the MonadNameRecord
// (Rust MonadNameRecord::try_from(&PeerEntry)).
func (p BootstrapPeerConfig) NameRecord() (peerdisc.MonadNameRecord, error) {
	e, err := p.PeerEntry()
	if err != nil {
		return peerdisc.MonadNameRecord{}, err
	}
	return peerdisc.MonadNameRecordFromPeerEntry(e)
}

// LoadBootstrapPeersFile reads a JSON array of BootstrapPeerConfig and
// returns verified records keyed by NodeId (self is filtered by the caller
// as upstream does: peers whose pubkey equals self are skipped upstream).
func LoadBootstrapPeersFile(path string) ([]BootstrapPeerConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var peers []BootstrapPeerConfig
	if err := json.Unmarshal(b, &peers); err != nil {
		return nil, fmt.Errorf("bootstrap peers file: %w", err)
	}
	return peers, nil
}

// BootstrapRecords converts a peers-file list into verified
// NodeId → MonadNameRecord (skipping self and invalid signatures, as
// upstream's bootstrap_peers collector does).
func BootstrapRecords(peers []BootstrapPeerConfig, selfID types.NodeId) map[types.NodeId]peerdisc.MonadNameRecord {
	out := map[types.NodeId]peerdisc.MonadNameRecord{}
	for _, p := range peers {
		nr, err := p.NameRecord()
		if err != nil {
			continue
		}
		id, err := nr.RecoverPubKey()
		if err != nil || id == selfID {
			continue
		}
		out[id] = nr
	}
	return out
}

// SelfBootstrapPeer builds this node's signed BootstrapPeerConfig — the
// genesis/devnet record emission (upstream self_record + self_name_record_sig
// assertion in main.rs).
func SelfBootstrapPeer(key *crypto.SecpKeyPair, advertise netip.Addr, tcpPort, udpPort, authPort, directUDP, encTCP uint16, seq uint64) BootstrapPeerConfig {
	nr := peerdisc.NewNameRecordWithPorts(advertise, tcpPort, udpPort, authPort, directUDP, encTCP, seq)
	mnr := peerdisc.NewMonadNameRecord(nr, key)
	pk := key.PubKey()
	return BootstrapPeerConfig{
		Address:          advertise.String(),
		TCPPort:          tcpPort,
		UDPPort:          udpPort,
		RecordSeqNum:     seq,
		Secp256k1Pubkey:  hex.EncodeToString(pk[:]),
		NameRecordSig:    hex.EncodeToString(mnr.Signature.Serialize()),
		AuthPort:         authPort,
		DirectUDPPort:    directUDP,
		EncryptedTCPPort: encTCP,
	}
}

// WriteBootstrapPeer writes one peers-file entry as JSON.
func WriteBootstrapPeer(path string, p BootstrapPeerConfig) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
