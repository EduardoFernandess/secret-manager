# secret-manager

Local encrypted vault for environment variables and small files. Master keys are derived with Argon2id; payloads use AES-256-GCM.

## Stack

- **Rust** — CLI vault tool
- **Argon2id** — password-based key derivation
- **AES-256-GCM** — authenticated encryption
- **Clap** — subcommands
- **zeroize** — sensitive material cleanup helpers

## What was built

- Vault init, set, get, and list for named secrets
- File encrypt / decrypt helpers for dotenv-style files
- Configurable vault path (`--vault`)
- Master password read from the terminal (not argv)
- Unit tests for crypto and vault round-trips

## Run

```bash
cargo run -- init
cargo run -- set DATABASE_URL 'postgres://localhost/app'
cargo run -- get DATABASE_URL
cargo run -- list
cargo run -- encrypt-file .env
cargo run -- decrypt-file .env.enc
```

Use a non-default vault file:

```bash
cargo run -- --vault path/to/vault.json list
```

### Tests

```bash
cargo test
```

## Security notes

This is a local learning/demo vault. Keep the master password strong, do not commit `vault.json` or `.env` files, and treat lost passwords as unrecoverable ciphertext.
