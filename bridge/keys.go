package bridge

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"

	"github.com/abhijitkrm/monadbft-go/crypto"
)

// MonadKeyFile — the node's MonadBFT consensus identity, stored as JSON
// alongside comet's priv_validator_key.json. secp256k1 = NodeId/signing,
// BLS = cert key. (x/consensuskeys will eventually bind these on-chain.)
type MonadKeyFile struct {
	SecpSecretKey string `json:"secp_secret_key"` // 32B hex
	BlsSecretKey  string `json:"bls_secret_key"`  // 32B hex (ikm)
}

// ValidatorBinding — one entry of the genesis validator binding file:
// the app's ed25519 consensus pubkey bound to MonadBFT secp+BLS pubkeys.
// This stands in for the x/consensuskeys registry until it ships.
type ValidatorBinding struct {
	ConsPubKey string `json:"cons_pubkey"` // 32B ed25519 hex
	SecpPubKey string `json:"secp_pubkey"` // 33B compressed hex
	BlsPubKey  string `json:"bls_pubkey"`  // 48B compressed hex
}

type validatorsFile struct {
	Validators []ValidatorBinding `json:"validators"`
}

// LoadOrGenMonadKey — load the consensus key file, generating+writing a
// fresh one if absent.
func LoadOrGenMonadKey(path string) (secp *crypto.SecpKeyPair, bls *crypto.BlsKeyPair, err error) {
	if raw, err := os.ReadFile(path); err == nil {
		var f MonadKeyFile
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", path, err)
		}
		sk, err := hex.DecodeString(f.SecpSecretKey)
		if err != nil || len(sk) != 32 {
			return nil, nil, fmt.Errorf("%s: bad secp_secret_key", path)
		}
		ikm, err := hex.DecodeString(f.BlsSecretKey)
		if err != nil || len(ikm) != 32 {
			return nil, nil, fmt.Errorf("%s: bad bls_secret_key", path)
		}
		secp, err = crypto.SecpKeyPairFromBytes(sk)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		bls, err = crypto.BlsKeyPairFromBytes(ikm)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		return secp, bls, nil
	}

	var sk, ikm [32]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(ikm[:]); err != nil {
		return nil, nil, err
	}
	secp, err = crypto.SecpKeyPairFromBytes(sk[:])
	if err != nil {
		return nil, nil, err
	}
	bls, err = crypto.BlsKeyPairFromBytes(ikm[:])
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, err
	}
	raw, err := json.MarshalIndent(MonadKeyFile{
		SecpSecretKey: hex.EncodeToString(sk[:]),
		BlsSecretKey:  hex.EncodeToString(ikm[:]),
	}, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, nil, err
	}
	return secp, bls, nil
}

// LoadValidators — the genesis validator binding file: cons pubkey →
// MonadBFT pubkeys for every validator. Order matches the file.
func LoadValidators(path string) ([]Validator, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load validator bindings: %w", err)
	}
	var f validatorsFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(f.Validators) == 0 {
		return nil, fmt.Errorf("%s: no validators", path)
	}
	out := make([]Validator, 0, len(f.Validators))
	for i, vb := range f.Validators {
		cp, err := hex.DecodeString(vb.ConsPubKey)
		if err != nil || len(cp) != 32 {
			return nil, fmt.Errorf("validators[%d]: bad cons_pubkey", i)
		}
		sp, err := hex.DecodeString(vb.SecpPubKey)
		if err != nil {
			return nil, fmt.Errorf("validators[%d]: bad secp_pubkey", i)
		}
		secpPub, err := crypto.SecpPubKeyFromBytes(sp)
		if err != nil {
			return nil, fmt.Errorf("validators[%d]: %w", i, err)
		}
		bp, err := hex.DecodeString(vb.BlsPubKey)
		if err != nil || len(bp) != 48 {
			return nil, fmt.Errorf("validators[%d]: bad bls_pubkey", i)
		}
		var blsPub [48]byte
		copy(blsPub[:], bp)
		var consPub cmted25519.PubKey
		consPub = append(consPub, cp...)
		out = append(out, PubValidator(secpPub, blsPub, consPub))
	}
	return out, nil
}

// SelfBinding — derive a single-validator binding from the local keys +
// the comet priv_validator (single-node chains need no binding file).
func SelfBinding(secp *crypto.SecpKeyPair, bls *crypto.BlsKeyPair, consPub cmted25519.PubKey) Validator {
	v := PubValidator(secp.PubKey(), [48]byte{}, consPub)
	copy(v.BlsPub[:], bls.PubKey().Compress())
	v.Secp = secp
	v.Bls = bls
	return v
}
