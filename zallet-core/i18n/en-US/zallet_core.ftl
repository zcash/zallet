# Copyright 2024 The Electric Coin Company
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

### Localization for strings in the zallet binary

## Terms (not to be localized)

-zcash = Zcash
-zallet = zallet
-zcashd = zcashd
-zebrad = zebrad

-systemd = systemd

-zallet-add-rpc-user = {-zallet} add-rpc-user

-allow-warnings = --allow-warnings
-allow-alpha-example = --this-is-alpha-code-and-you-will-need-to-recreate-the-example-later
-allow-alpha-migration = --this-is-alpha-code-and-you-will-need-to-redo-the-migration-later
-allow-multiple-wallet-imports = --allow-multiple-wallet-imports
-datadir = --datadir
-db_dump = db_dump
-zcashd-install-dir = --zcashd-install-dir

-legacy_pool_seed_fingerprint = legacy_pool_seed_fingerprint
-zallet_toml = zallet.toml

-cfg-rpc-auth = rpc.auth
-cfg-rpc-auth-password = rpc.auth.password
-cfg-rpc-auth-pwhash = rpc.auth.pwhash

## Usage

usage-header = Usage

flags-header = Options

## Command prompts & output

cmd-add-rpc-user-prompt = Enter password:
cmd-add-rpc-user-instructions = Add this to your {-zallet_toml} file:
cmd-seed-fingerprint = Seed fingerprint: {$seedfp}
cmd-import-mnemonic-prompt = Enter mnemonic:

cmd-generate-encryption-identity-public-key = Public key: {$pubkey}
cmd-generate-encryption-identity-written = Encryption identity written to {$path}
cmd-generate-encryption-identity-write-failed = Failed to write encryption identity to {$path}: {$error}
cmd-generate-encryption-identity-exists = An encryption identity already exists at {$path}; refusing to overwrite it to avoid irrecoverable key loss.
cmd-generate-encryption-identity-passphrase-prompt = Enter passphrase to encrypt the identity:
cmd-generate-encryption-identity-passphrase-confirm = Confirm passphrase:
cmd-generate-encryption-identity-passphrase-mismatch = Passphrases do not match

cmd-migrate-wallet-passphrase-prompt = Enter the passphrase for the encrypted zcashd wallet:
cmd-migrate-wallet-passphrase-wrong = The passphrase was incorrect; please try again.

## Startup messages

warn-config-unused = Config option '{$option}' is not yet implemented in {-zallet}; ignoring its value.

rpc-bare-password-auth-info = Using '{-cfg-rpc-auth-password}' authorization
rpc-bare-password-auth-warn =
    The use of '{-cfg-rpc-auth-password}' is less secure, because credentials are
    configured in plain text. It is recommended that locally-run instances switch to
    cookie-based auth, or otherwise to use '{-cfg-rpc-auth-pwhash}' credentials generated with
    '{-zallet-add-rpc-user}'.
rpc-pwhash-auth-info = Using '{-cfg-rpc-auth-pwhash}' authorization

rpc-cookie-generated = Generated RPC authentication cookie {$path}
rpc-cookie-read-failed = Failed to read cookie file: {$error}
rpc-cookie-user-conflict = Configured user conflicts with cookie auth username, skipping cookie generation

## zallet.toml example messages

example-alpha-code =
    This command is not stable. You will need to rerun this command again once {-zallet}
    is stable to migrate your config correctly. To confirm you are aware of this, use
    '{-allow-alpha-example}'.

## zcash.conf migration messages

migrate-warnings = Some {-zcashd} options are not supported by {-zallet}:
migrate-warn-daemon =
    {-zallet} does not support the {-zcashd} option '{$option}'; instead you should
    use {-systemd} or similar to manage {-zallet} as a background service.
migrate-warn-disablewallet =
    The {-zcashd} config file has '{$option}' enabled, meaning that this {-zcashd}
    node's wallet was not being used. Check that you do intend to migrate its
    configuration to {-zallet}.
migrate-warn-paytxfee = '{$option}' is set, but {-zallet} only supports ZIP 317 fees.
migrate-warn-rpcport =
    {-zcashd} used the same port for both node and wallet RPC methods. {-zallet}
    has its own port for wallet RPC methods separate from the underlying {-zebrad}
    node, so the '{$option}' setting is not being migrated. If you want to change
    the default {-zallet} port, set '{$port}' in the {$rpc} section of the {-zallet}
    config file.
migrate-warn-sprout-migration =
    {-zallet} does not support Sprout, so the Sprout-to-Sapling migration option
    '{$option}' will not be migrated over.
migrate-warn-cli-only =
    {-zcashd} supported configuring '{$option}' via both a CLI flag and a config
    file entry. {-zallet} does not support it as a config file entry; you will
    instead need to start {-zallet} with the CLI flag '{$flag}'.
migrate-warn-unsupported =
    {-zallet} does not support an equivalent of the {-zcashd} option '{$option}',
    so its configured value '{$value}' is not being migrated. If this option is
    required for your use case, please get in touch with the {-zcash} developers
    as soon as possible to discuss alternatives.

migrate-alpha-code =
    This command is not stable, and parts of your {-zcashd} data may not get
    migrated correctly. You will need to rerun this command again once {-zallet}
    is stable to migrate your config correctly. To confirm you are aware of
    this, use '{-allow-alpha-migration}'.

migrate-config-written = {-zallet} config written to {$conf}

migrate-wallet-legacy-seed-fp =
    Importing zcashd legacy account for seed fingerprint '{$seed_fp}'. If you wish to
    enable legacy zcashd semantics for wallet RPC methods, you should set
    '{-legacy_pool_seed_fingerprint}' to this value in '{-zallet_toml}'.",

## General errors

err-kind-generic = Error
err-kind-init = Failed to initialize {-zallet}
err-kind-chain = An error occurred while accessing chain data.
err-kind-sync = Failed to synchronize {-zallet}

err-init-cannot-find-home-dir =
    Cannot find home directory for the default datadir. Use '{-datadir}' to set
    the datadir directly.
err-init-failed-to-create-lockfile = Failed to create a lockfile at {$path}: {$error}
err-init-failed-to-read-lockfile = Failed to read lockfile at {$path}: {$error}
err-init-zallet-already-running =
    Cannot obtain a lock on data directory {$datadir}. {-zallet} is probably already running.

err-init-config-db-mismatch =
    The wallet database at {$db_path} was created for network type
    {$db_network_type}, but the config is using network type
    {$config_network_type}. A wallet database is permanently tied to one network;
    set 'network' back to {$db_network_type}, or use a different data directory to
    create a fresh {$config_network_type} wallet.
err-init-db-incompatible-alpha =
    This wallet database was created by an incompatible alpha version of {-zallet}.
    To use this {-zallet} release, start again with a fresh Zallet wallet or a
    new data directory.
err-init-db-invalid-zallet-version =
    The wallet database recorded an invalid {-zallet} version '{$version}':
    {$err}

err-init-identity-not-found = Encryption identity file could not be located at {$path}. An identity can be generated using generate-encryption-identity.
err-init-identity-not-passphrase-encrypted = {$path} is not encrypted with a passphrase
err-init-path-not-utf8 = {$path} is not currently supported (not UTF-8)
err-init-identity-not-usable = Identity file at {$path} is not usable: {$error}
err-init-rpc-auth-invalid = Invalid '{-cfg-rpc-auth}' configuration
err-config-file-not-found = Configuration file at {$path} does not exist.
err-config-file-invalid = Failed to parse configuration file at {$path}: {$error}
err-init-incompatible-consensus =
    The backing full node follows consensus rules that this {-zallet} build cannot
    interpret correctly, so {-zallet} cannot maintain a correct view of the chain.
    Either the full node follows a network upgrade that this build does not recognize,
    or it activates a recognized upgrade at a height that differs from what this build
    expects.
    Incompatible network upgrades: {$upgrades}.
    Upgrade {-zallet} to a release whose consensus rules match the full node.
warn-init-pending-incompatible-consensus =
    The backing full node is scheduled to activate consensus rules that this {-zallet}
    build cannot interpret correctly. {-zallet} will operate normally until the chain
    reaches height {$height}, then shut down to avoid presenting an incorrect view of the
    chain.
    Pending incompatible network upgrades: {$upgrades}.
    Upgrade {-zallet} to a release whose consensus rules match the full node before then.
warn-init-consensus-divergence-reached =
    The chain has reached height {$height}, where the backing full node's consensus rules
    diverge from what this {-zallet} build can interpret. Shutting down to avoid an
    incorrect view of the chain. Upgrade {-zallet} to a release whose consensus rules match
    the full node.
err-config-backend-mismatch = The config file selects the '{$configured}' chain backend, but this binary provides the '{$provided}' backend. Run the `zallet` launcher (or the matching backend binary) instead, or change the config file's `backend` key.

## Keystore errors

err-keystore-missing-recipients = The wallet has not been set up to store key material securely.
rec-keystore-missing-recipients = Have you run '{$init_cmd}'?
err-keystore-already-initialized = Keystore age recipients already initialized
err-wallet-locked = Wallet is locked

## Account errors

err-account-not-found = Account does not exist
err-account-no-payment-source = Account has no payment source.

# errors in migration of configuration data from the zcashd `zcash.conf` config file format

err-migrate-allow-warnings = To allow a migration with warnings, use '{-allow-warnings}'
err-migrate-duplicate-zcashd-option =
    {-zcashd} option '{$option}' does not support multiple values,
    but appears multiple times in {$conf}
    Remove or comment out any duplicates so that it is only set once,
    then re-run this command.
err-migrate-invalid-line = Invalid line '{$line}' in {$conf}
err-migrate-invalid-zcashd-option = Invalid value '{$value}' for {-zcashd} option '{$option}'
err-migrate-multiple-related-zcashd-options =
    {-zcashd} option '{$option}' collides with '{$prev}', but both appear in
    {$conf}
    Remove one of the conflicting options, then re-run this command.
err-migrate-unknown-zcashd-option = Unknown {-zcashd} option '{$option}'

# errors in migration of wallet data from the zcashd `wallet.dat` database format

err-failed-seed-fingerprinting =
    Zallet was unable to import invalid seed data, likely due to the seed having
    an invalid length.
err-migrate-wallet-multi-import-disabled =
    The {-allow-multiple-wallet-imports} flag must be provided to allow the
    import of more than a single {-zcashd} `wallet.dat` file into {-zallet}.
err-migrate-wallet-duplicate-import =
    The {-zcashd} wallet containing seed with fingerprint '{$seed_fp}' has
    already been imported.
err-migrate-wallet-bdb-parse =
    An error occurred in parsing the {-zcashd} wallet file at '{$path}': '{$err}'
err-migrate-wallet-db-dump-not-found =
    The {-db_dump} command line utility was not found. Either set the
    {-zcashd-install-dir} command-line argument to the local zcashd installation
    root (which must contain the `zcutil/bin/` utilities) or ensure that {-db_dump}
    is available on the system `$PATH`.
err-migrate-wallet-db-dump =
    An error occurred in extracting wallet data from '{$path}': '{$err}'
err-migrate-wallet-seed-absent =
    The {-zcashd} wallet file did not contain HD seed information. Wallets from
    prior to the Sapling network upgrade are not supported by this migration
    tool.
err-migrate-wallet-invalid-mnemonic =
    The {-zcashd} wallet file contained invalid mnemonic seed phrase data and
    may be corrupt: '{$err}'
err-migrate-wallet-key-decoding=
    The {-zcashd} wallet file contained invalid mnemonic transparent secret key
    data and may be corrupt: '{$err}'
err-migrate-wallet-key-data=
    The {-zcashd} wallet file contained invalid key data and may be corrupt:
    '{$err}'
err-migrate-wallet-network-mismatch =
    The {-zcashd} wallet being imported is for the '{$wallet_network}' network,
    but this {-zallet} instance is configured for '{$zallet_network}'
err-migrate-wallet-regtest =
    Migration of regtest wallets is not yet supported.
err-migrate-wallet-storage =
    An database error occurred in wallet migration. This is indicative of a
    programming error; please report the following error to (TBD): '{$err}'
err-migrate-wallet-invalid-chain-data =
    Invalid chain data was encountered in wallet migration. This is indicative of a
    programming error; please report the following error to (TBD): '{$err}'
err-migrate-wallet-key-decoding =
    An error occurred decoding key material: '{$err}'.
err-migrate-wallet-tx-fetch =
    An error occurred fetching transaction data: '{$err}'.
err-migrate-wallet-data-parse=
    An error occurred parsing zcashd wallet data: '{$err}'.
err-migrate-wallet-invalid-account-id =
    Error encountered in wallet migration: '{$account_id}' is not a valid ZIP
    32 account identifier.
err-migrate-wallet-all-unmined =
    All transactions in the wallet are unmined; cannot determine effective
    consensus branch ID for pre-v5 transactions.
err-migrate-secret-non-english-mnemonic =
    The wallet contains a mnemonic seed phrase using a wordlist other than
    English; only English mnemonics can be imported.
err-migrate-secret-fingerprint-encoding =
    The wallet records an invalid seed fingerprint '{$fingerprint}'.
err-migrate-secret-fingerprint-mismatch =
    A stored seed does not match the fingerprint '{$fingerprint}' it was
    recorded under; the wallet data may be corrupt.
err-migrate-secret-transparent-key-decoding =
    The wallet contains a transparent secret key that is not a valid WIF
    encoding for this network.
err-migrate-secret-transparent-key-mismatch =
    A transparent secret key does not correspond to the public key it was
    recorded under; the wallet data may be corrupt.
err-migrate-secret-sapling-key-decoding =
    An error occurred decoding a Sapling spending key: '{$err}'.
err-migrate-secret-sapling-key-mismatch =
    A Sapling spending key does not correspond to the viewing key it was
    recorded under; the wallet data may be corrupt.
err-migrate-wallet-export =
    An error occurred exporting the {-zcashd} wallet to a ZeWIF document: '{$err}'
err-migrate-wallet-import =
    An error occurred importing the ZeWIF document into the wallet database: '{$err}'
err-migrate-wallet-secret-store =
    An error occurred storing wallet secrets in the keystore: '{$err}'
err-migrate-wallet-encrypted-secrets =
    The ZeWIF document's secret material is encrypted; decrypt it before import.

err-ux-A = Did {-zallet} not do what you expected? Could the error be more useful?
err-ux-B = Tell us
# Put (len(A) - len(B) - 41) spaces here.
err-ux-C = {"                    "}

## Limit errors

err-excess-orchard-actions =
    Including {$count} Orchard {$kind} would exceed the current limit of
    {$limit} actions, which exists to prevent memory exhaustion. Restart with
    '{$config}' where {$bound} to allow the wallet to attempt to construct this
    transaction.

## Privacy policy errors

err-privpol-no-privacy-not-allowed =
    This transaction would have no privacy, which is not enabled by default.
    THIS WILL AFFECT YOUR PRIVACY. Resubmit with the '{$parameter}' parameter
    set to '{$policy}' if you wish to allow this transaction to proceed anyway.
err-privpol-linking-addrs-not-allowed =
    This transaction would spend transparent funds received by multiple unified
    addresses within the same account, which is not enabled by default because
    it will publicly link those addresses together.
err-privpol-fully-transparent-not-allowed =
    This transaction would both spend transparent funds and have transparent
    recipients or change, which is not enabled by default because it will
    publicly reveal transaction participants and amounts.
err-privpol-transparent-sender-not-allowed =
    This transaction would spend transparent funds, which is not enabled by
    default because it will publicly reveal transaction senders and amounts.
err-privpol-transparent-recipient-not-allowed =
    This transaction would have transparent recipients, which is not enabled by
    default because it will publicly reveal transaction recipients and amounts.
err-privpol-transparent-change-not-allowed =
    This transaction would have transparent change, which is not enabled by
    default because it will publicly reveal the change address and amounts.
err-privpol-revealing-amount-not-allowed =
    Could not send to the {$pool} shielded pool without spending non-{$pool}
    funds, which would reveal transaction amounts.
err-privpol-transparent-receiver-not-allowed =
    This transaction would send to a transparent receiver of a unified address,
    which is not enabled by default because it will publicly reveal transaction
    recipients and amounts.
err-privpol-revealing-receiver-amounts-not-allowed =
    Could not send to a shielded receiver of a unified address without spending
    funds from a different pool, which would reveal transaction amounts.
rec-privpol-privacy-weakening =
    THIS MAY AFFECT YOUR PRIVACY. Resubmit with the '{$parameter}' parameter set
    to '{$policy}' or weaker if you wish to allow this transaction to proceed
    anyway.

## RPC method errors

err-rpc-convert-tex-invalid-address = Invalid address
err-rpc-convert-tex-not-p2pkh = Address is not a transparent p2pkh address

## RPC CLI errors

err-rpc-cli-conn-failed = Failed to connect to the Zallet wallet's JSON-RPC port.
err-rpc-cli-invalid-param = Invalid parameter '{$parameter}'
err-rpc-cli-no-server = No JSON-RPC port is available.
err-rpc-cli-request-failed = JSON-RPC request failed: {$error}

## zallet manpage

man-zallet-about = A {-zcash} wallet.

man-zallet-description =
    {-zallet} is a {-zcash} wallet.
