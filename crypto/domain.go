// Package crypto ports monad-crypto / monad-secp / monad-bls.
// Signing domains are length-prefixed ASCII strings terminated by '\n';
// the first byte is the byte-length of the remainder (<128) and is
// part of the signed preimage.
package crypto

// Signing domain prefixes, identical to monad-crypto/src/signing_domain.rs.
// Each starts with a length byte and ends with '\n'.
var (
	DomainConsensusMessage = []byte("\x1amonad/consensus-message/1\n")
	DomainTip              = []byte("\x0cmonad/tip/1\n")
	DomainVote             = []byte("\x0dmonad/vote/1\n")
	DomainTimeout          = []byte("\x10monad/timeout/1\n")
	DomainNoEndorsement    = []byte("\x17monad/no-endorsement/1\n")
	DomainRoundSignature   = []byte("\x18monad/round-signature/1\n")
	DomainNameRecord       = []byte("\x14monad/name-record/1\n")
	DomainRaptorcastAppMsg = []byte("\x1fmonad/raptorcast-app-message/1\n")
	DomainRaptorcastChunk  = []byte("\x19monad/raptorcast-chunk/1\n")
)

// withDomain returns prefix || msg — the preimage that gets hashed/signed.
func withDomain(prefix, msg []byte) []byte {
	out := make([]byte, 0, len(prefix)+len(msg))
	out = append(out, prefix...)
	out = append(out, msg...)
	return out
}
