#!/usr/bin/env bash
# node-backup.sh — cold snapshot / restore of an evmd --engine=monadbft home.
#
#   node-backup.sh snapshot <home> <dest-dir> [--include-keys]
#   node-backup.sh restore  <archive.tar.gz> <home> [--force-old-safety]
#   node-backup.sh verify   <archive.tar.gz>
#
# The node MUST be stopped: application.db, bridge-results/ and blocks/ are
# separate databases with no cross-store atomic snapshot, and a hot copy of a
# LevelDB/Pebble directory can be torn. On boot the bridge reconciles the
# store tip against the forkpoint (rollback / index backfill), so a *cold*
# copy of the full data/ dir is always self-consistent.
#
# Safety: data/monadbft/safety.rlp holds this validator's vote watermarks.
# Restoring an OLDER safety.rlp onto a validator that voted after the backup
# can make it vote twice in a round (equivocation). `restore` therefore keeps
# the home's existing safety.rlp when one is present and is newer; it
# refuses to install the archived one over a newer file unless
# --force-old-safety is given (only for a fresh identity / disaster recovery
# where the validator has been offline far longer than one round).
set -euo pipefail

die() { echo "node-backup: $*" >&2; exit 1; }

require_stopped() {
  local home="$1"
  if pgrep -f -- "--home[= ]${home}( |$)" >/dev/null 2>&1; then
    die "a process is running with --home ${home}; stop the node first"
  fi
}

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi; }

snapshot() {
  local home="${1:?home}" dest="${2:?dest-dir}" keys="${3:-}"
  home="$(cd "$home" && pwd)"
  [ -d "$home/data" ] && [ -d "$home/config" ] || die "$home is not an evmd home (no data/ or config/)"
  require_stopped "$home"
  mkdir -p "$dest"
  local ts name excludes=()
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  name="$(basename "$(dirname "$home")")-$(basename "$home")-${ts}"
  if [ "$keys" != "--include-keys" ]; then
    # keys are backed up separately (encrypted, offline) — never in data snapshots
    excludes=(--exclude=config/monad.key.json --exclude=config/priv_validator_key.json --exclude=config/node_key.json)
  fi
  tar -C "$home" "${excludes[@]}" -czf "$dest/$name.tar.gz" config data
  sha "$dest/$name.tar.gz" > "$dest/$name.tar.gz.sha256"
  echo "snapshot: $dest/$name.tar.gz"
  [ "$keys" = "--include-keys" ] && echo "WARNING: archive contains validator private keys — store encrypted"
  return 0
}

verify() {
  local archive="${1:?archive}"
  [ -f "$archive.sha256" ] || die "missing $archive.sha256"
  local want got
  want="$(awk '{print $1}' "$archive.sha256")"
  got="$(sha "$archive" | awk '{print $1}')"
  [ "$want" = "$got" ] || die "checksum mismatch for $archive"
  tar -tzf "$archive" | grep -q '^data/monadbft/forkpoint.rlp$' || die "archive has no data/monadbft/forkpoint.rlp"
  echo "verify: ok ($archive)"
}

restore() {
  local archive="${1:?archive}" home="${2:?home}" force="${3:-}"
  verify "$archive"
  mkdir -p "$home"
  home="$(cd "$home" && pwd)"
  require_stopped "$home"
  local ts stash safety_live=""
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  if [ -f "$home/data/monadbft/safety.rlp" ]; then
    safety_live="$(mktemp)"
    cp -p "$home/data/monadbft/safety.rlp" "$safety_live"
  fi
  if [ -d "$home/data" ]; then
    stash="$home/data.pre-restore-$ts"
    mv "$home/data" "$stash"
    echo "restore: previous data moved to $stash"
  fi
  tar -C "$home" -xzf "$archive"
  local restored="$home/data/monadbft/safety.rlp"
  if [ -n "$safety_live" ]; then
    if [ "$force" = "--force-old-safety" ]; then
      echo "restore: --force-old-safety: using the archived safety.rlp (live copy saved at $safety_live)"
    elif [ ! -f "$restored" ] || [ "$safety_live" -nt "$restored" ]; then
      # watermarks only grow and the file is rewritten on change, so the
      # newer mtime is the higher watermark (tar preserves mtimes)
      cp -p "$safety_live" "$restored"
      echo "restore: kept the node's existing (newer) safety.rlp — vote watermarks never move backwards"
      rm -f "$safety_live"
    else
      echo "restore: archived safety.rlp is newer than the node's; using it"
      rm -f "$safety_live"
    fi
  elif [ -f "$restored" ]; then
    echo "WARNING: no live safety.rlp existed; the archived watermarks are in use."
    echo "         If this validator voted after the snapshot was taken, keep it offline"
    echo "         until the network has advanced well past that point before starting."
  fi
  echo "restore: done — start the node; it reconciles to its forkpoint and blocksyncs to tip"
}

case "${1:-}" in
  snapshot) shift; snapshot "$@" ;;
  restore)  shift; restore "$@" ;;
  verify)   shift; verify "$@" ;;
  *) sed -n '2,6p' "$0"; exit 2 ;;
esac
