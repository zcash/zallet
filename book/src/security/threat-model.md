# Threat model

Zallet is software that holds spending authority. The threats that matter are
the ones that can redirect that authority, leak the secrets backing it, or
coerce the wallet into accepting state the operator did not author. This page
scopes what Zallet defends against, what it does not, and what it relies on the
operator to do.

## In scope

### Secret key material confidentiality

Spending keys, mnemonic phrases, and standalone Sapling and transparent keys
are stored in `wallet.db` as [age] ciphertexts. Decrypting any of them
requires the age identity file (and its passphrase, if set), which the
operator stores separately from the database. See
[Wallet encryption](../concepts/encryption.md).

The identity file can itself be passphrase-encrypted. With a passphrase set,
the keystore starts **locked**: operations that need spending keys fail with
"Wallet is locked" until `walletpassphrase` supplies the passphrase, and
`walletlock` re-locks it.

### Per-read integrity of stored secrets

When the wallet decrypts a stored secret, it recomputes the fingerprint or
public key from the decrypted material and requires it to match the row key
before using it. This catches ciphertext substitution and cached-change-address
tampering of individual rows: an attacker who replaces a keystore ciphertext
with an encryption of their own key material is detected at the point of use,
because the recomputed fingerprint does not match the row that selected it.

These per-read re-derive checks were landed in #643 and cover mnemonic seeds,
standalone Sapling extended spending keys, standalone transparent secret keys,
and seed-derived account UFVKs at spend time.

### RPC channel hygiene

The JSON-RPC interface is the primary control surface an attacker targets when
the wallet is running. Zallet defends the channel itself:

- **Method-name-only RPC logging.** The RPC middleware logs only the method
  name and an `is_error` flag, never call parameters or response bodies, so
  secrets passed to methods like `walletpassphrase` or `z_importkey` do not
  appear in logs (#677).
- **No secrets in argv or environment variables.** Sensitive parameters are
  read from files or stdin via the `@PATH` convention (#722). The
  `ZALLET_IDENTITY_PASSPHRASE` environment variable was removed because sibling
  processes could read it (#677).
- **Filesystem permissions.** The datadir is set to `0700` on lock, and
  `wallet.db` is created with mode `0600` so journal, WAL, and sidecar files
  inherit restrictive permissions (#677).
- **Authentication required on every request.** A random cookie credential is
  written to `{datadir}/.cookie` at startup, and password users can be
  provisioned with `zallet add-rpc-user`. The cookie file grants full wallet
  access and must be protected by datadir permissions. See
  [Operating Zallet](../operations/README.md#securing-the-json-rpc-interface).
- **Loopback binding by default.** The RPC server is disabled unless the config
  sets `rpc.bind`. Non-loopback binding is discouraged; see the operations
  guide for the secure remote-access pattern (SSH tunnel or VPN).

### Supply chain integrity

Every release artifact is produced on GitHub Actions with an auditable workflow
identity, emits a [SLSA v1.0] Build L3 provenance statement, and is
reproducible. See [Supply Chain Security (SLSA)](slsa.md).

## Out of scope

### Full filesystem compromise

If an attacker can write arbitrary files in the datadir as the wallet user
while Zallet is running, or between sessions, they can mutate `wallet.db`, the
identity file, the config file, and any sidecar. Zallet cannot secure its own
filesystem against its operator; that is the operating system's job. We assume
the datadir lives on a host the operator controls, with filesystem permissions
set as documented above.

A sub-case worth naming: an attacker who obtains a copy of `wallet.db` (from a
backup service, a DB dump, a misconfigured restore) and modifies it before it
is restored. The per-read re-derive checks catch direct ciphertext-substitution
attacks against individual secret rows, but an attacker who can rewrite the
database has a wider surface than single-row swaps. The operator's defense is
to treat any restored `wallet.db` as untrusted: verify its provenance, and rely
on the identity file (which the attacker does not have) as the second factor
that prevents spending.

### Plaintext transaction history and viewing keys

`wallet.db` as a whole is **not** encrypted. Spending key material inside it is
encrypted to the age identity, but transaction history, addresses, and viewing
keys are stored in the clear. Anyone who reads the file learns the wallet's
full transaction history and viewing keys, though they cannot spend without the
identity. This is a deliberate design choice documented in
[Wallet encryption](../concepts/encryption.md): encrypting the whole database
would conflict with the existing age-based scheme and would still leave the
identity file as the single decryption secret. The operator's defense is
filesystem permissions and encrypting backups before upload (see
[Backup and restore](../guide/backup.md#encrypting-backups-before-upload)).

### Backup confidentiality

A `wallet.db` copy stored in a third-party backup service is outside Zallet's
reach. The operator must encrypt it before upload. See
[Encrypting backups before upload](../guide/backup.md#encrypting-backups-before-upload).

### Side-channel and physical attacks

Cold-boot attacks, DMA, a compromised hypervisor, and other physical or
side-channel attacks against the host are out of scope. Any of these can
recover keys from memory regardless of the wallet software in use.

## What an attacker with a DB copy can and cannot do

| Attacker capability | Requires identity file? | Caught by |
|---|---|---|
| Read transaction history and viewing keys | No | Nothing. This is the plaintext-DB trade-off. |
| Attempt offline brute force of age ciphertexts | No (but needs the ciphertext) | Computationally infeasible if the identity passphrase is strong. |
| Spend funds | **Yes** | The spending key is age-encrypted; the attacker cannot decrypt it without the identity file. |
| Substitute a keystore ciphertext with their own key | No | Per-read re-derive check: the recomputed fingerprint does not match the row key. |
| Substitute a cached transparent change address | No | Per-read re-derive check: change outputs are re-derived from the USK before broadcast. |
| Forge a UFVK signature over a swapped UFVK | No | Computationally infeasible without the spending key (the signature is produced at import time by the USK). |
| Append an age recipient to silently receive future ciphertexts | No | Not caught by per-read checks. The operator's defense is encrypting backups and verifying restored DB provenance. |

[age]: https://age-encryption.org/
[SLSA v1.0]: https://slsa.dev/spec/v1.0
[#643]: https://github.com/zcash/zallet/pull/643
[#677]: https://github.com/zcash/zallet/pull/677
[#722]: https://github.com/zcash/zallet/pull/722