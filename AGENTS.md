# Agent instructions

Read [`PRINCIPLES.md`](PRINCIPLES.md) before changing this repository. Preserve
API compatibility with the desktop client unless a versioned migration is part
of the change. Never store or log secrets, raw license keys, stable raw device
identifiers, signing private keys, HMAC secrets, or authorization headers.

Before push run `npm run typecheck`, `npm test`, and any relevant local Worker/D1
integration tests. Record security-sensitive decisions and local/CI evidence
under `codex/`.

