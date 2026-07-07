use documented::Documented;
use jsonrpsee::core::RpcResult;
use sapling::bundle::{OutputDescription, SpendDescription};
use schemars::JsonSchema;
use serde::Serialize;
use transparent::bundle::{TxIn, TxOut};
use zcash_encoding::ReverseHex;
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::TxVersion;
use zcash_protocol::{TxId, value::ZatBalance};
use zcash_script::script::{Asm, Code};

use super::decode_script::{TransparentScript, script_to_json};
use crate::{
    components::{
        chain::{Chain, ChainView},
        database::DbConnection,
        json_rpc::{
            server::LegacyCode,
            utils::{
                JsonZec, JsonZecBalance, parse_txid, value_from_zat_balance, value_from_zatoshis,
            },
        },
    },
    network::Network,
};

/// Response to a `getrawtransaction` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The `getrawtransaction` response.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(untagged)]
pub(crate) enum ResultType {
    /// The serialized, hex-encoded data for `txid`.
    Concise(String),

    /// An object describing the transaction in detail.
    Verbose(Box<Transaction>),
}

/// Verbose information about a transaction.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct Transaction {
    /// Whether specified block is in the active chain or not.
    ///
    /// Only present with explicit `blockhash` argument.
    #[serde(skip_serializing_if = "Option::is_none")]
    in_active_chain: Option<bool>,

    /// The serialized, hex-encoded data for the transaction identified by `txid`.
    hex: String,

    #[serde(flatten)]
    inner: TransactionDetails,

    /// The hash of the block that the transaction is mined in, if any.
    ///
    /// Omitted if the transaction is not known to be mined in any block.
    #[serde(skip_serializing_if = "Option::is_none")]
    blockhash: Option<String>,

    /// The height of the block that the transaction is mined in, or -1 if that block is
    /// not in the current best chain.
    ///
    /// Omitted if `blockhash` is either omitted or unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<i32>,

    /// The number of confirmations the transaction has, or 0 if the block it is mined in
    /// is not in the current best chain.
    ///
    /// Omitted if `blockhash` is either omitted or unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmations: Option<u32>,

    /// The transaction time in seconds since epoch (Jan 1 1970 GMT).
    ///
    /// This is always identical to `blocktime`.
    ///
    /// Omitted if `blockhash` is either omitted or not in the current best chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<i64>,

    /// The block time in seconds since epoch (Jan 1 1970 GMT) for the block that the
    /// transaction is mined in.
    ///
    /// Omitted if `blockhash` is either omitted or not in the current best chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    blocktime: Option<i64>,
}

/// Verbose information about a transaction.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct TransactionDetails {
    /// The transaction ID (same as provided).
    txid: String,

    /// The transaction's authorizing data commitment.
    ///
    /// For pre-v5 transactions this will be `ffff..ffff`.
    ///
    /// Encoded as a byte-reversed hex string to match `txid`.
    authdigest: String,

    /// The network-serialized transaction size.
    size: u64,

    /// Whether the `overwintered` flag is set.
    overwintered: bool,

    /// The transaction version.
    version: u32,

    /// The version group ID.
    ///
    /// Omitted if `overwintered` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    versiongroupid: Option<String>,

    /// The lock time.
    locktime: u32,

    /// The block height after which the transaction expires.
    ///
    /// Omitted if `overwintered` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    expiryheight: Option<u32>,

    /// The transparent inputs to the transaction.
    vin: Vec<TransparentInput>,

    /// The transparent outputs from the transaction.
    vout: Vec<TransparentOutput>,

    /// The Sprout spends and outputs of the transaction.
    #[cfg(zallet_unimplemented)]
    vjoinsplit: Vec<JoinSplit>,

    /// The net value of Sapling Spends minus Outputs in ZEC.
    ///
    /// Omitted if `version < 4`.
    #[serde(rename = "valueBalance")]
    #[serde(skip_serializing_if = "Option::is_none")]
    value_balance: Option<JsonZecBalance>,

    /// The net value of Sapling Spends minus Outputs in zatoshis.
    ///
    /// Omitted if `version < 4`.
    #[serde(rename = "valueBalanceZat")]
    #[serde(skip_serializing_if = "Option::is_none")]
    value_balance_zat: Option<i64>,

    /// Omitted if `version < 4`.
    #[serde(rename = "vShieldedSpend")]
    #[serde(skip_serializing_if = "Option::is_none")]
    v_shielded_spend: Option<Vec<SaplingSpend>>,

    /// Omitted if `version < 4`.
    #[serde(rename = "vShieldedOutput")]
    #[serde(skip_serializing_if = "Option::is_none")]
    v_shielded_output: Option<Vec<SaplingOutput>>,

    /// The Sapling binding signature, encoded as a hex string.
    ///
    /// Omitted if `version < 4`, or both `vShieldedSpend` and `vShieldedOutput` are empty.
    #[serde(rename = "bindingSig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    binding_sig: Option<String>,

    /// JSON object with Orchard-specific information.
    ///
    /// Omitted if `version < 5`.
    #[serde(skip_serializing_if = "Option::is_none")]
    orchard: Option<Orchard>,

    /// The `joinSplitSig` public validating key.
    ///
    /// Encoded as a byte-reversed hex string for legacy reasons.
    ///
    /// Omitted if `version < 2` or `vjoinsplit` is empty.
    #[cfg(zallet_unimplemented)]
    #[serde(rename = "joinSplitPubKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    join_split_pub_key: Option<String>,

    /// The Sprout binding signature, encoded as a hex string.
    ///
    /// Omitted if `version < 2` or `vjoinsplit` is empty.
    #[cfg(zallet_unimplemented)]
    #[serde(rename = "joinSplitSig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    join_split_sig: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(super) struct TransparentInput {
    /// The coinbase `scriptSig`, encoded as a hex string.
    ///
    /// Omitted if this is not a coinbase transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    coinbase: Option<String>,

    /// The transaction ID of the output being spent.
    ///
    /// Omitted if this is a coinbase transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,

    /// The index of the output being spent within the transaction identified by `txid`.
    ///
    /// Omitted if this is a coinbase transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    vout: Option<u32>,

    /// Omitted if this is a coinbase transaction.
    #[serde(rename = "scriptSig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    script_sig: Option<TransparentScriptSig>,

    /// The script sequence number.
    sequence: u32,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(super) struct TransparentScriptSig {
    /// The assembly string representation of the script.
    asm: String,

    /// The serialized script, encoded as a hex string.
    hex: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(super) struct TransparentOutput {
    /// The value in ZEC.
    value: JsonZec,

    /// The value in zatoshis.
    #[serde(rename = "valueZat")]
    value_zat: u64,

    /// The value in zatoshis.
    #[serde(rename = "valueSat")]
    value_sat: u64,

    /// The index of the output within the transaction's `vout` field.
    n: u16,

    #[serde(rename = "scriptPubKey")]
    script_pub_key: TransparentScriptPubKey,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(super) struct TransparentScriptPubKey {
    /// The serialized script, encoded as a hex string.
    hex: String,

    #[serde(flatten)]
    inner: TransparentScript,
}

#[cfg(zallet_unimplemented)]
#[derive(Clone, Debug, Serialize, JsonSchema)]
struct JoinSplit {
    /// The public input value in ZEC.
    vpub_old: JsonZec,

    /// The public input value in zatoshis.
    #[serde(rename = "vpub_oldZat")]
    vpub_old_zat: u64,

    /// The public output value in ZEC.
    vpub_new: JsonZec,

    /// The public output value in zatoshis.
    #[serde(rename = "vpub_newZat")]
    vpub_new_zat: u64,

    /// The anchor.
    ///
    /// Encoded as a byte-reversed hex string for legacy reasons.
    anchor: String,

    /// Array of input note nullifiers.
    ///
    /// Encoded as byte-reversed hex strings for legacy reasons.
    nullifiers: Vec<String>,

    /// Array of output note commitments.
    ///
    /// Encoded as byte-reversed hex strings for legacy reasons.
    commitments: Vec<String>,

    /// The onetime public key used to encrypt the ciphertexts.
    ///
    /// Encoded as a byte-reversed hex string for legacy reasons.
    #[serde(rename = "onetimePubKey")]
    onetime_pub_key: String,

    /// The random seed.
    ///
    /// Encoded as a byte-reversed hex string for legacy reasons.
    #[serde(rename = "randomSeed")]
    random_seed: String,

    /// Array of input note MACs.
    ///
    /// Encoded as byte-reversed hex strings for legacy reasons.
    macs: Vec<String>,

    /// The zero-knowledge proof, encoded as a hex string.
    proof: String,

    /// Array of output note ciphertexts, encoded as hex strings.
    ciphertexts: Vec<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(super) struct SaplingSpend {
    /// Value commitment to the input note.
    ///
    /// Encoded as a byte-reversed hex string for legacy reasons.
    cv: String,

    /// Merkle root of the Sapling note commitment tree.
    ///
    /// Encoded as a byte-reversed hex string for legacy reasons.
    anchor: String,

    /// The nullifier of the input note.
    ///
    /// Encoded as a byte-reversed hex string for legacy reasons.
    nullifier: String,

    /// The randomized public key for `spendAuthSig`.
    ///
    /// Encoded as a byte-reversed hex string for legacy reasons.
    rk: String,

    /// A zero-knowledge proof using the Sapling Spend circuit, encoded as a hex string.
    proof: String,

    /// A signature authorizing this Spend, encoded as a hex string.
    #[serde(rename = "spendAuthSig")]
    spend_auth_sig: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(super) struct SaplingOutput {
    /// Value commitment to the output note.
    ///
    /// Encoded as a byte-reversed hex string for legacy reasons.
    cv: String,

    /// The u-coordinate of the note commitment for the output note.
    ///
    /// Encoded as a byte-reversed hex string for legacy reasons.
    cmu: String,

    /// A Jubjub public key.
    ///
    /// Encoded as a byte-reversed hex string for legacy reasons.
    #[serde(rename = "ephemeralKey")]
    ephemeral_key: String,

    /// The output note encrypted to the recipient, encoded as a hex string.
    #[serde(rename = "encCiphertext")]
    enc_ciphertext: String,

    /// A ciphertext enabling the sender to recover the output note, encoded as a hex
    /// string.
    #[serde(rename = "outCiphertext")]
    out_ciphertext: String,

    /// A zero-knowledge proof using the Sapling Output circuit, encoded as a hex string.
    proof: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(super) struct Orchard {
    /// The Orchard Actions for the transaction.
    actions: Vec<OrchardAction>,

    /// The net value of Orchard Actions in ZEC.
    #[serde(rename = "valueBalance")]
    value_balance: JsonZecBalance,

    /// The net value of Orchard Actions in zatoshis.
    #[serde(rename = "valueBalanceZat")]
    value_balance_zat: i64,

    /// The Orchard bundle flags.
    ///
    /// Omitted if `actions` is empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    flags: Option<OrchardFlags>,

    /// A root of the Orchard note commitment tree at some block height in the past,
    /// encoded as a hex string.
    ///
    /// Omitted if `actions` is empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor: Option<String>,

    /// Encoding of aggregated zk-SNARK proofs for Orchard Actions, encoded as a hex
    /// string.
    ///
    /// Omitted if `actions` is empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<String>,

    /// An Orchard binding signature on the SIGHASH transaction hash, encoded as a hex
    /// string.
    ///
    /// Omitted if `actions` is empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "bindingSig")]
    binding_sig: Option<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(super) struct OrchardAction {
    /// A value commitment to the net value of the input note minus the output note,
    /// encoded as a hex string.
    cv: String,

    /// The nullifier of the input note, encoded as a hex string.
    nullifier: String,

    /// The randomized validating key for `spendAuthSig`, encoded as a hex string.
    rk: String,

    /// The x-coordinate of the note commitment for the output note, encoded as a hex
    /// string.
    cmx: String,

    /// An encoding of an ephemeral Pallas public key, encoded as a hex string.
    #[serde(rename = "ephemeralKey")]
    ephemeral_key: String,

    /// The output note encrypted to the recipient, encoded as a hex string.
    #[serde(rename = "encCiphertext")]
    enc_ciphertext: String,

    /// A ciphertext enabling the sender to recover the output note, encoded as a hex
    /// string.
    #[serde(rename = "outCiphertext")]
    out_ciphertext: String,

    /// A signature authorizing the spend in this Action, encoded as a hex string.
    #[serde(rename = "spendAuthSig")]
    spend_auth_sig: String,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(super) struct OrchardFlags {
    /// Whether spends are enabled in this Orchard bundle.
    #[serde(rename = "enableSpends")]
    enable_spends: bool,

    /// Whether outputs are enabled in this Orchard bundle.
    #[serde(rename = "enableOutputs")]
    enable_outputs: bool,
}

pub(super) const PARAM_TXID_DESC: &str = "The ID of the transaction to fetch.";
pub(super) const PARAM_VERBOSE_DESC: &str = "If 0, return a string of hex-encoded data. If non-zero, return a JSON object with information about `txid`";
pub(super) const PARAM_BLOCKHASH_DESC: &str = "The block in which to look for the transaction.";

pub(crate) async fn call<C: Chain>(
    wallet: &DbConnection,
    chain: C,
    txid_str: &str,
    verbose: Option<u64>,
    blockhash: Option<String>,
) -> Response {
    let txid = parse_txid(txid_str)?;
    let verbose = verbose.is_some_and(|v| v != 0);

    // If a block hash is provided, the lookup is restricted to that specific block.
    let requested_block = blockhash
        .map(|s| {
            ReverseHex::decode(&s)
                .map(BlockHash)
                .ok_or_else(|| LegacyCode::InvalidParameter.with_static("invalid blockhash"))
        })
        .transpose()?;

    let chain_view = chain
        .snapshot()
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    let tx = match chain_view.get_transaction(txid).await {
        Ok(Some(tx)) => Ok(tx),
        Ok(None) => Err(LegacyCode::InvalidAddressOrKey
            .with_static("No such mempool or blockchain transaction")),
        Err(e) => Err(LegacyCode::Database.with_message(e.to_string())),
    }?;

    // If the caller restricted the lookup to a specific block, the transaction must be
    // mined in that block. `in_active_chain` then reports whether that block is part of
    // the main chain (mirroring `zcashd`, which only sets this field when `blockhash` is
    // given).
    let in_active_chain = match requested_block {
        None => None,
        Some(requested) => {
            if tx.block_hash() != Some(requested) {
                return Err(LegacyCode::InvalidAddressOrKey
                    .with_static("No such transaction found in the provided block"));
            }

            // The requested block is in the active chain iff it is the canonical block at
            // the transaction's mined height.
            let mined_height = tx
                .mined_height()
                .expect("a transaction with a block hash has a mined height");
            let canonical = chain_view
                .get_block_header(mined_height)
                .await
                .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
                .map(|header| header.hash());
            Some(canonical == Some(requested))
        }
    };

    let blockhash = tx.block_hash().map(|hash| hash.to_string());
    let height = tx
        .mined_height()
        .and_then(|h| i32::try_from(u32::from(h)).ok());
    let chain_tip = chain_view
        .tip()
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;
    let confirmations = tx.mined_height().map(|h| chain_tip.height() + 1 - h);
    let blocktime = tx.block_time().map(i64::from);

    let tx_hex = hex::encode(tx.raw());
    if !verbose {
        return Ok(ResultType::Concise(tx_hex));
    }

    let size = tx.raw().len() as u64;
    let (tx, _) = tx.into_parts();

    Ok(ResultType::Verbose(Box::new(Transaction {
        in_active_chain,
        hex: tx_hex,
        inner: tx_to_json(wallet.params(), tx, size),
        blockhash,
        height,
        confirmations,
        time: blocktime,
        blocktime,
    })))
}

/// Equivalent of `TxToJSON` in `zcashd` with null `hashBlock`.
pub(super) fn tx_to_json(
    params: &Network,
    tx: zcash_primitives::transaction::Transaction,
    size: u64,
) -> TransactionDetails {
    let overwintered = tx.version().has_overwinter();

    let (vin, vout) = match tx.transparent_bundle() {
        Some(bundle) => (
            bundle
                .vin
                .iter()
                .map(|tx_in| TransparentInput::encode(tx_in, bundle.is_coinbase()))
                .collect(),
            bundle
                .vout
                .iter()
                .zip(0..)
                .map(|txout| TransparentOutput::encode(params, txout))
                .collect(),
        ),
        _ => (vec![], vec![]),
    };

    #[cfg(zallet_unimplemented)]
    let (vjoinsplit, join_split_pub_key, join_split_sig) = match tx.sprout_bundle() {
        Some(bundle) if !bundle.joinsplits.is_empty() => (
            bundle.joinsplits.iter().map(JoinSplit::encode).collect(),
            Some(ReverseHex::decode(bundle.joinsplit_pubkey)),
            Some(hex::encode(bundle.joinsplit_sig)),
        ),
        _ => (vec![], None, None),
    };

    let (value_balance, value_balance_zat, v_shielded_spend, v_shielded_output, binding_sig) =
        if let Some(bundle) = tx.sapling_bundle() {
            (
                Some(value_from_zat_balance(*bundle.value_balance())),
                Some(bundle.value_balance().into()),
                Some(
                    bundle
                        .shielded_spends()
                        .iter()
                        .map(SaplingSpend::encode)
                        .collect(),
                ),
                Some(
                    bundle
                        .shielded_outputs()
                        .iter()
                        .map(SaplingOutput::encode)
                        .collect(),
                ),
                Some(hex::encode(<[u8; 64]>::from(
                    bundle.authorization().binding_sig,
                ))),
            )
        } else if matches!(tx.version(), TxVersion::Sprout(_) | TxVersion::V3) {
            // Omitted if `version < 4`.
            (None, None, None, None, None)
        } else {
            // Present but empty, except for `bindingSig`.
            (
                Some(value_from_zat_balance(ZatBalance::zero())),
                Some(0),
                Some(vec![]),
                Some(vec![]),
                None,
            )
        };

    let orchard = tx
        .version()
        .has_orchard()
        .then(|| Orchard::encode(tx.orchard_bundle()));

    TransactionDetails {
        txid: tx.txid().to_string(),
        authdigest: ReverseHex::encode(&tx.auth_commitment().as_bytes().try_into().unwrap()),
        size,
        overwintered,
        version: tx.version().header() & 0x7FFFFFFF,
        versiongroupid: overwintered.then(|| format!("{:08x}", tx.version().version_group_id())),
        locktime: tx.lock_time(),
        expiryheight: overwintered.then(|| tx.expiry_height().into()),
        vin,
        vout,
        #[cfg(zallet_unimplemented)]
        vjoinsplit,
        value_balance,
        value_balance_zat,
        v_shielded_spend,
        v_shielded_output,
        binding_sig,
        orchard,
        #[cfg(zallet_unimplemented)]
        join_split_pub_key,
        #[cfg(zallet_unimplemented)]
        join_split_sig,
    }
}

impl TransparentInput {
    pub(super) fn encode(tx_in: &TxIn<transparent::bundle::Authorized>, is_coinbase: bool) -> Self {
        let script_bytes = &tx_in.script_sig().0.0;
        let script_hex = hex::encode(script_bytes);

        if is_coinbase {
            Self {
                coinbase: Some(script_hex),
                txid: None,
                vout: None,
                script_sig: None,
                sequence: tx_in.sequence(),
            }
        } else {
            // For scriptSig, we pass `true` since there may be signatures
            let asm = Code(script_bytes.to_vec()).to_asm(true);

            Self {
                coinbase: None,
                txid: Some(TxId::from_bytes(*tx_in.prevout().hash()).to_string()),
                vout: Some(tx_in.prevout().n()),
                script_sig: Some(TransparentScriptSig {
                    asm,
                    hex: script_hex,
                }),
                sequence: tx_in.sequence(),
            }
        }
    }
}

impl TransparentOutput {
    pub(super) fn encode(params: &Network, (tx_out, n): (&TxOut, u16)) -> Self {
        let script_bytes = &tx_out.script_pubkey().0.0;
        let script_code = Code(script_bytes.to_vec());

        let script_pub_key = TransparentScriptPubKey {
            hex: hex::encode(script_bytes),
            inner: script_to_json(params, &script_code),
        };

        Self {
            value: value_from_zatoshis(tx_out.value()),
            value_zat: tx_out.value().into_u64(),
            value_sat: tx_out.value().into_u64(),
            n,
            script_pub_key,
        }
    }
}

#[cfg(zallet_unimplemented)]
impl JoinSplit {
    fn encode(js_desc: &zcash_primitives::transaction::components::sprout::JsDescription) -> Self {
        // https://github.com/zcash/librustzcash/issues/1943
        todo!("Requires zcash_primitives changes")
    }
}

impl SaplingSpend {
    pub(super) fn encode(spend: &SpendDescription<sapling::bundle::Authorized>) -> Self {
        Self {
            cv: ReverseHex::encode(&spend.cv().to_bytes()),
            anchor: ReverseHex::encode(&spend.anchor().to_bytes()),
            nullifier: ReverseHex::encode(&spend.nullifier().0),
            rk: ReverseHex::encode(&<[u8; 32]>::from(*spend.rk())),
            proof: hex::encode(spend.zkproof()),
            spend_auth_sig: hex::encode(<[u8; 64]>::from(*spend.spend_auth_sig())),
        }
    }
}

impl SaplingOutput {
    pub(super) fn encode(output: &OutputDescription<sapling::bundle::GrothProofBytes>) -> Self {
        Self {
            cv: ReverseHex::encode(&output.cv().to_bytes()),
            cmu: ReverseHex::encode(&output.cmu().to_bytes()),
            ephemeral_key: ReverseHex::encode(&output.ephemeral_key().0),
            enc_ciphertext: hex::encode(output.enc_ciphertext()),
            out_ciphertext: hex::encode(output.out_ciphertext()),
            proof: hex::encode(output.zkproof()),
        }
    }
}

impl Orchard {
    pub(super) fn encode(
        bundle: Option<&orchard::Bundle<orchard::bundle::Authorized, ZatBalance>>,
    ) -> Self {
        match bundle {
            None => Self {
                actions: vec![],
                value_balance: value_from_zat_balance(ZatBalance::zero()),
                value_balance_zat: 0,
                flags: None,
                anchor: None,
                proof: None,
                binding_sig: None,
            },
            Some(bundle) => Self {
                actions: bundle.actions().iter().map(OrchardAction::encode).collect(),
                value_balance: value_from_zat_balance(*bundle.value_balance()),
                value_balance_zat: bundle.value_balance().into(),
                flags: Some(OrchardFlags {
                    enable_spends: bundle.flags().spends_enabled(),
                    enable_outputs: bundle.flags().outputs_enabled(),
                }),
                anchor: Some(hex::encode(bundle.anchor().to_bytes())),
                proof: Some(hex::encode(bundle.authorization().proof())),
                binding_sig: Some(hex::encode(<[u8; 64]>::from(
                    bundle.authorization().binding_signature(),
                ))),
            },
        }
    }
}

impl OrchardAction {
    fn encode(
        action: &orchard::Action<
            orchard::primitives::redpallas::Signature<orchard::primitives::redpallas::SpendAuth>,
        >,
    ) -> Self {
        Self {
            cv: hex::encode(action.cv_net().to_bytes()),
            nullifier: hex::encode(action.nullifier().to_bytes()),
            rk: hex::encode(<[u8; 32]>::from(action.rk())),
            cmx: hex::encode(action.cmx().to_bytes()),
            ephemeral_key: hex::encode(action.encrypted_note().epk_bytes),
            enc_ciphertext: hex::encode(action.encrypted_note().enc_ciphertext),
            out_ciphertext: hex::encode(action.encrypted_note().out_ciphertext),
            spend_auth_sig: hex::encode(<[u8; 64]>::from(action.authorization())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAINNET: &Network = &Network::Consensus(zcash_protocol::consensus::Network::MainNetwork);
    const V1_TX_HEX: &str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";

    #[test]
    fn decode_v1_transaction() {
        let tx = super::super::decode_raw_transaction::call(MAINNET, V1_TX_HEX).unwrap();
        assert_eq!(tx.size, 193);
        assert_eq!(tx.version, 1);
        assert_eq!(tx.locktime, 0);
        assert!(!tx.overwintered);
        assert!(tx.versiongroupid.is_none());
        assert!(tx.expiryheight.is_none());
        assert_eq!(tx.vin.len(), 1);
        assert_eq!(tx.vout.len(), 1);
    }

    /// P2PKH scriptSig with sighash decode.
    ///
    /// Test vector from zcashd `qa/rpc-tests/decodescript.py:122-125`.
    /// Tests that scriptSig asm correctly decodes the sighash type suffix.
    #[test]
    fn scriptsig_asm_p2pkh_with_sighash() {
        let scriptsig = hex::decode(
            "47304402207174775824bec6c2700023309a168231ec80b82c6069282f5133e6f11cbb04460220570edc55c7c5da2ca687ebd0372d3546ebc3f810516a002350cac72dfe192dfb014104d3f898e6487787910a690410b7a917ef198905c27fb9d3b0a42da12aceae0544fc7088d239d9a48f2828a15a09e84043001f27cc80d162cb95404e1210161536"
        ).unwrap();
        let asm = Code(scriptsig).to_asm(true);
        assert_eq!(
            asm,
            "304402207174775824bec6c2700023309a168231ec80b82c6069282f5133e6f11cbb04460220570edc55c7c5da2ca687ebd0372d3546ebc3f810516a002350cac72dfe192dfb[ALL] 04d3f898e6487787910a690410b7a917ef198905c27fb9d3b0a42da12aceae0544fc7088d239d9a48f2828a15a09e84043001f27cc80d162cb95404e1210161536"
        );
    }

    /// Test that scriptSig uses sighash decoding (true) and scriptPubKey does not (false).
    ///
    /// Verifies correct wiring: `TransparentInput::encode` passes `true` to `to_asm()`
    /// while `TransparentOutput::encode` passes `false`.
    #[test]
    fn scriptsig_vs_scriptpubkey_sighash_handling() {
        // A simple signature with SIGHASH_ALL (0x01) suffix
        // This is a minimal DER signature followed by 0x01
        let sig_with_sighash = hex::decode(
            "483045022100ab4c5228e6f8290a5c7e1c4afedbb32b6a6e95b9f873d2e1d5f6a8c3b4e7f09102205d6a8c3b4e7f091ab4c5228e6f8290a5c7e1c4afedbb32b6a6e95b9f873d2e1d01"
        ).unwrap();

        // With sighash decode (for scriptSig), should show [ALL]
        let asm_with_decode = Code(sig_with_sighash.clone()).to_asm(true);
        assert!(
            asm_with_decode.ends_with("[ALL]"),
            "scriptSig should decode sighash suffix"
        );

        // Without sighash decode (for scriptPubKey), should show raw hex
        let asm_without_decode = Code(sig_with_sighash).to_asm(false);
        assert!(
            !asm_without_decode.contains("[ALL]"),
            "scriptPubKey should not decode sighash suffix"
        );
    }

    /// Test all sighash type suffixes are decoded correctly.
    ///
    /// Sighash types from zcashd `src/test/script_tests.cpp:949-977` (`script_GetScriptAsm`).
    #[test]
    fn sighash_type_decoding() {
        // Base DER signature (without sighash byte)
        let base_sig = "3045022100ab4c5228e6f8290a5c7e1c4afedbb32b6a6e95b9f873d2e1d5f6a8c3b4e7f09102205d6a8c3b4e7f091ab4c5228e6f8290a5c7e1c4afedbb32b6a6e95b9f873d2e1d";

        let test_cases = [
            ("01", "[ALL]"),
            ("02", "[NONE]"),
            ("03", "[SINGLE]"),
            ("81", "[ALL|ANYONECANPAY]"),
            ("82", "[NONE|ANYONECANPAY]"),
            ("83", "[SINGLE|ANYONECANPAY]"),
        ];

        for (sighash_byte, expected_suffix) in test_cases {
            let sig_hex = format!("48{base_sig}{sighash_byte}");
            let sig_bytes = hex::decode(&sig_hex).unwrap();
            let asm = Code(sig_bytes).to_asm(true);
            assert!(
                asm.ends_with(expected_suffix),
                "Sighash byte {sighash_byte} should produce suffix {expected_suffix}, got: {asm}"
            );
        }
    }

    /// Test that numeric opcodes are formatted as zcashd expects.
    ///
    /// Test vectors from zcashd `qa/rpc-tests/decodescript.py:54,82`.
    #[test]
    fn asm_numeric_opcodes_match_zcashd() {
        // From decodescript.py:54 - script '5100' (OP_1 OP_0) should produce '1 0'
        let script = hex::decode("5100").unwrap();
        let asm = Code(script).to_asm(false);
        assert_eq!(asm, "1 0");

        // OP_1NEGATE (0x4f) should produce '-1'
        let script = hex::decode("4f").unwrap();
        let asm = Code(script).to_asm(false);
        assert_eq!(asm, "-1");

        // From decodescript.py:82 - 2-of-3 multisig pattern should use '2' and '3'
        // Script: OP_2 <pubkey> <pubkey> <pubkey> OP_3 OP_CHECKMULTISIG
        let public_key = "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2";
        let push_public_key = format!("21{public_key}");
        let script_hex = format!("52{push_public_key}{push_public_key}{push_public_key}53ae");
        let script = hex::decode(&script_hex).unwrap();
        let asm = Code(script).to_asm(false);
        let expected = format!("2 {public_key} {public_key} {public_key} 3 OP_CHECKMULTISIG");
        assert_eq!(asm, expected);
    }
}
