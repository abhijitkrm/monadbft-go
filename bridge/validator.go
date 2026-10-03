package bridge

import (
	"fmt"
	"math/big"

	sdktypes "github.com/cosmos/cosmos-sdk/types"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/abhijitkrm/monadbft-go/chaincfg"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/metrics"
)

// secp256k1 curve order for the signature-structure screen.
var secpN = ethcrypto.S256().Params().N

// EvmBlockValidator — the production BlockValidator for the bridge lane,
// mirroring upstream EthBlockValidator: header/body payload-id consistency,
// the author's BLS round signature (randao reveal), proposal size/gas
// limits, and per-tx static checks (SDK decode + EVM chain-id + gas limit +
// signature structure). Execution-level validation (nonce, balance, fees)
// stays in the app's FinalizeBlock — same split as upstream, where account
// checks need extending-branch state the ABCI seam doesn't expose.
type EvmBlockValidator struct {
	decode  sdktypes.TxDecoder // nil → skip per-tx decode (non-evmd apps)
	chainID *big.Int           // EVM chain-id; nil → skip chain-id check
}

// NewEvmBlockValidator — decoder/chainID source the app supplies (evmd:
// raw.TxConfig().TxDecoder() and the EVM module's chain config).
func NewEvmBlockValidator(decode sdktypes.TxDecoder, chainID *big.Int) *EvmBlockValidator {
	return &EvmBlockValidator{decode: decode, chainID: chainID}
}

func (v *EvmBlockValidator) Validate(
	header cstypes.ConsensusBlockHeader,
	body cstypes.ConsensusBlockBody,
	authorPubKey *crypto.BlsPubKey,
	chainConfig chaincfg.Config,
	m *metrics.Metrics,
) (*cstypes.ConsensusFullBlock, error) {
	// author signature on the round (randao reveal) — must verify against the
	// author's cert pubkey or the proposer could bias mix_hash. Nil author
	// means the caller is re-checking an already-committed block
	// (maybeStartConsensus bootstrap) — same skip as upstream.
	if authorPubKey != nil &&
		!cstypes.VerifyRoundSignature(header.RoundSignature, header.BlockRound, *authorPubKey) {
		return nil, fmt.Errorf("bridge: invalid round signature")
	}

	params := chainConfig.GetChainRevision(header.BlockRound).ChainParams()

	eb, ok := body.Inner.ExecutionBody.(*EvmBody)
	if !ok {
		return nil, fmt.Errorf("bridge: unexpected body type %T", body.Inner.ExecutionBody)
	}
	if uint64(len(eb.Txs)) > params.TxLimit {
		return nil, fmt.Errorf("bridge: %d txs > tx_limit %d", len(eb.Txs), params.TxLimit)
	}
	var total uint64
	for _, tx := range eb.Txs {
		total += uint64(len(tx))
	}
	if total > params.ProposalByteLimit {
		return nil, fmt.Errorf("bridge: %d tx bytes > proposal_byte_limit %d",
			total, params.ProposalByteLimit)
	}
	if v.decode != nil {
		for i, raw := range eb.Txs {
			if err := v.checkTx(raw, params); err != nil {
				return nil, fmt.Errorf("bridge: tx %d: %w", i, err)
			}
		}
	}

	block, err := cstypes.NewFullBlock(header, body)
	if err != nil {
		return nil, err
	}
	return &block, nil
}

// checkTx — static per-tx checks: SDK decode, then for each MsgEthereumTx
// the chain-id, gas-limit, and signature-structure screens.
func (v *EvmBlockValidator) checkTx(raw []byte, params *chaincfg.Params) error {
	tx, err := v.decode(raw)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	for _, msg := range tx.GetMsgs() {
		etx, ok := msg.(*evmtypes.MsgEthereumTx)
		if !ok {
			continue // non-EVM messages: ante/exec path validates
		}
		t := etx.AsTransaction()
		if t == nil {
			return fmt.Errorf("malformed eth tx")
		}
		if t.Protected() && v.chainID != nil && t.ChainId().Cmp(v.chainID) != 0 {
			return fmt.Errorf("chain_id %v != %v", t.ChainId(), v.chainID)
		}
		if t.Gas() > params.ProposalGasLimit {
			return fmt.Errorf("gas %d > proposal_gas_limit %d", t.Gas(), params.ProposalGasLimit)
		}
		if _, r, s := t.RawSignatureValues(); r == nil || s == nil ||
			r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(secpN) >= 0 || s.Cmp(secpN) >= 0 {
			return fmt.Errorf("invalid signature structure")
		}
	}
	return nil
}
