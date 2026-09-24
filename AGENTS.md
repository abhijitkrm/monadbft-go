# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

Go port of MonadBFT (`github.com/category-labs/monad-bft`) for the Cosmos-EVM
stack. Two modules:

- `.` — `github.com/abhijitkrm/monadbft-go` — consensus core. **No Cosmos /
  CometBFT / geth-app dependencies** — keep it pure.
- `bridge/` — `github.com/abhijitkrm/monadbft-go/bridge` — ABCI/evmd
  integration. All cosmos deps live here (`replace` directives point at the
  local cosmos-evm checkout and this repo's parent dir).

Docs: `README.md`, `docs/integration.md`, `docs/migration.md`, `PLAN.md`.

## Commits

- Conventional prefixes: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`,
  `chore:`.
- **Do NOT add `Generated with …` or `Co-Authored-By: Devin` trailers** —
  per repo owner's instruction; history was rewritten to remove them.

## Testing

```bash
go build ./... && go vet ./... && go test ./...        # core module
cd bridge && go test -tags=test -v .                   # bridge (needs -tags=test)
```

`gofmt` clean before committing. Bridge tests spin up real in-process evmd
apps — see `docs/integration.md` for the app requirements (mempool heightsync
notification, slashing signing infos, consensus params, ethsecp256k1 funded
accounts).
