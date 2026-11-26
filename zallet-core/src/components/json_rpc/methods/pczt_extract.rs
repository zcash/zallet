//! PCZT extract method — extract the final transaction from a completed PCZT.
//!
//! Extraction finalizes the transparent spends and then verifies the shielded
//! proofs and signatures before producing the transaction bytes. A PCZT that is
//! missing proofs (see [`super::pczt_prove`]) or shielded signatures (see
//! [`super::pczt_sign`]) will be rejected here rather than producing an invalid
//! transaction. Transparent inputs are *not* verified beyond the spend
//! finalizer's structural checks — script execution is deferred to the network,
//! so a transaction with an invalid transparent signature extracts successfully
//! and is rejected at broadcast.
//!
//! For a PCZT this wallet created, the extracted transaction is also recorded
//! in the wallet, so its spent notes are tracked as pending before the
//! transaction is ever broadcast. A PCZT created elsewhere cannot be recorded
//! (the wallet has no proposal metadata for it); the wallet learns of it only
//! when it appears on chain.

use documented::Documented;
use jsonrpsee::core::RpcResult;
use jsonrpsee::types::ErrorObjectOwned;
use orchard::circuit::VerifyingKey;
use pczt::Pczt;
use pczt::roles::spend_finalizer::SpendFinalizer;
use pczt::roles::tx_extractor::TransactionExtractor;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use sapling::circuit::{OutputVerifyingKey, SpendVerifyingKey};
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{WalletRead, wallet::extract_and_store_transaction_from_pczt};
use zcash_client_sqlite::{ReceivedNoteId, util::SystemClock};
use zcash_primitives::transaction::Transaction;

use super::pczt_common::{
    PROP_BACKEND_PROPOSAL_INFO, PROVING_SLOTS, circuit_version_for_branch, decode_pczt_base64,
    orchard_verifying_key, sapling_verifying_keys,
};
use super::pczt_error::PcztError;
use crate::{
    components::{
        database::Database,
        json_rpc::{server::LegacyCode, utils::wallet_handle},
    },
    fl,
};

pub(crate) type Response = RpcResult<ResultType>;

/// Result containing the extracted transaction.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ExtractResult {
    /// The hex-encoded raw transaction.
    pub hex: String,
    /// The transaction ID.
    pub txid: String,
    /// Whether the wallet recorded the transaction before returning it.
    ///
    /// `true` for a PCZT this wallet created: the spent notes are tracked as
    /// pending from this point. `false` for a PCZT created elsewhere, which the
    /// wallet will only learn about when it appears on chain.
    pub stored: bool,
}

pub(crate) type ResultType = ExtractResult;

pub(super) const PARAM_PCZT_DESC: &str =
    "The base64-encoded PCZT to extract a final transaction from.";

/// Serializes an extracted transaction for the response.
///
/// A failure here is an internal inconsistency rather than bad input — the
/// transaction has already been built and verified — so the cause is carried in
/// the message.
fn serialize_transaction(tx: &Transaction) -> Result<Vec<u8>, ErrorObjectOwned> {
    let mut bytes = Vec::new();
    tx.write(&mut bytes).map_err(|e| {
        LegacyCode::Deserialization
            .with_message(fl!("err-pczt-serialize-transaction", error = e.to_string()))
    })?;
    Ok(bytes)
}

/// Finalizes a PCZT's transparent spends and extracts its transaction, without
/// recording it in the wallet.
fn extract_unrecorded(
    pczt: Pczt,
    (spend_vk, output_vk): (&SpendVerifyingKey, &OutputVerifyingKey),
    orchard_vk: Option<&VerifyingKey>,
) -> Result<Transaction, PcztError> {
    // Fold partial transparent signatures into their `script_sig`s.
    // This is a no-op when there are no transparent inputs.
    let pczt = SpendFinalizer::new(pczt)
        .finalize_spends()
        .map_err(PcztError::FinalizeSpends)?;

    let mut extractor = TransactionExtractor::new(pczt);
    extractor = extractor.with_sapling(spend_vk, output_vk);
    if let Some(vk) = orchard_vk {
        extractor = extractor.with_orchard(vk);
    }
    extractor
        .extract(UnwrapErr(SysRng))
        .map_err(PcztError::Extract)
}

/// Extracts a final, network-ready transaction from a completed PCZT.
///
/// The PCZT must already have all required proofs and signatures in place;
/// extraction verifies the shielded ones and fails otherwise. (Transparent
/// script signatures are checked by the network at broadcast, not here.)
pub(crate) async fn call(wallet: Database, pczt_base64: &str) -> Response {
    let pczt = decode_pczt_base64(pczt_base64)?;

    // One verifying key serves both the Orchard and Ironwood bundles: the
    // circuit version is a function of the PCZT's consensus branch. An unknown
    // branch gets no key, and the extractor rejects the PCZT itself.
    let orchard_vk =
        circuit_version_for_branch(*pczt.global().consensus_branch_id()).map(orchard_verifying_key);
    let (spend_vk, output_vk) = sapling_verifying_keys();

    // A PCZT created by this wallet carries the backend's proposal metadata,
    // which is what allows the extracted transaction to be recorded in the
    // wallet's database (marking its inputs as pending-spent). Without it, only
    // raw extraction is possible.
    let wallet_created = pczt
        .global()
        .proprietary()
        .contains_key(PROP_BACKEND_PROPOSAL_INFO);

    // Spend finalization and proof verification are CPU-bound (and generating
    // the Orchard verifying key on first use is expensive), so run them off the
    // async runtime, at bounded concurrency.
    let _permit = PROVING_SLOTS
        .acquire()
        .await
        .expect("the proving semaphore is never closed");

    // Acquire the database connection only once a proving slot is held, so a call
    // queued behind the semaphore does not sit on one of the pool's connections (see
    // `Database::handle`).
    let mut wallet = wallet_handle(&wallet).await?;

    let (tx_bytes, txid, stored): (Vec<u8>, String, bool) =
        crate::spawn_blocking!("pczt_extract", move || -> Result<_, ErrorObjectOwned> {
            if wallet_created {
                // Finalizes spends, verifies, stores the transaction in the
                // wallet database, and returns its ID.
                let txid = extract_and_store_transaction_from_pczt::<_, ReceivedNoteId>(
                    wallet.as_mut(),
                    &SystemClock,
                    &mut UnwrapErr(SysRng),
                    pczt,
                    Some((spend_vk, output_vk)),
                    orchard_vk,
                )
                .map_err(|e| {
                    LegacyCode::Verify
                        .with_message(fl!("err-pczt-extract-store", error = e.to_string()))
                })?;

                let tx = wallet
                    .get_transaction(txid)
                    .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
                    .ok_or_else(|| {
                        LegacyCode::Database
                            .with_message(fl!("err-pczt-stored-transaction-missing"))
                    })?;

                Ok((serialize_transaction(&tx)?, txid.to_string(), true))
            } else {
                let tx = extract_unrecorded(pczt, (spend_vk, output_vk), orchard_vk)?;

                Ok((serialize_transaction(&tx)?, tx.txid().to_string(), false))
            }
        })
        .await
        .map_err(|source| PcztError::TaskFailed {
            task: "pczt_extract",
            source,
        })??;

    Ok(ExtractResult {
        hex: hex::encode(tx_bytes),
        txid,
        stored,
    })
}

#[cfg(test)]
mod tests {
    use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer, signer::Signer};
    use proptest::prelude::*;
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    use secp256k1::{Message, PublicKey, SecretKey, ecdsa};
    use transparent::{
        address::TransparentAddress,
        bundle::{OutPoint, TxOut},
        sighash::SIGHASH_ALL,
        util::hash160,
    };
    use zcash_primitives::transaction::{
        builder::{BuildConfig, Builder, BundlePadding},
        fees::zip317::FeeRule,
    };
    use zcash_protocol::{
        consensus::{MAIN_NETWORK, MainNetwork, NetworkUpgrade, Parameters},
        value::{COIN, Zatoshis},
    };
    use zcash_script::{
        pattern::check_multisig,
        script::{self, Evaluable},
    };

    use super::super::pczt_common::sapling_verifying_keys;
    use super::extract_unrecorded;

    /// The most compressed public keys a P2SH multisig redeem script can hold while
    /// staying within the 520-byte limit on a script push.
    const MAX_MULTISIG_KEYS: usize = 15;

    /// `OP_0`, the dummy element `OP_CHECKMULTISIG` pops before the signatures.
    const OP_0: u8 = 0x00;
    /// `OP_PUSHDATA1`, followed by a one-byte length. A shorter push uses its length
    /// as the opcode.
    const OP_PUSHDATA1: u8 = 0x4c;
    /// `OP_PUSHDATA2`, followed by a two-byte little-endian length.
    const OP_PUSHDATA2: u8 = 0x4d;

    /// Encodes a script push of `data` as the consensus rules parse it.
    fn push(data: &[u8]) -> Vec<u8> {
        let len = data.len();
        let mut bytes = if len < usize::from(OP_PUSHDATA1) {
            vec![u8::try_from(len).expect("checked above")]
        } else if let Ok(len) = u8::try_from(len) {
            vec![OP_PUSHDATA1, len]
        } else {
            let len = u16::try_from(len).expect("a script push is at most 520 bytes");
            [&[OP_PUSHDATA2][..], &len.to_le_bytes()].concat()
        };
        bytes.extend_from_slice(data);
        bytes
    }

    /// A builder for a transaction that spends `coin`, held by the P2SH address of
    /// `redeem_script`, to `recipient`.
    fn spend_builder(
        redeem_script: &script::FromChain,
        coin: &TxOut,
        recipient: &TransparentAddress,
        output_value: Zatoshis,
    ) -> Builder<MainNetwork, ()> {
        let target_height = MAIN_NETWORK
            .activation_height(NetworkUpgrade::Nu5)
            .expect("NU5 is active on mainnet");
        let mut builder = Builder::new(
            MAIN_NETWORK,
            target_height,
            BuildConfig::Standard {
                sapling_anchor: None,
                orchard_anchor: None,
                ironwood_anchor: None,
                orchard_padding: BundlePadding::DEFAULT,
                ironwood_padding: BundlePadding::DEFAULT,
            },
        );
        builder
            .add_transparent_p2sh_input(
                redeem_script.clone(),
                OutPoint::new([0; 32], 0),
                coin.clone(),
            )
            .expect("the coin pays to the redeem script");
        builder
            .add_transparent_output(recipient, output_value)
            .expect("a P2PKH output is valid");
        builder
    }

    proptest! {
        // Each case signs and extracts a transaction, so take fewer samples than the
        // default 256; every multisig size is still very likely to be drawn.
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Extracting a PCZT that spends a P2SH multisig output produces the `scriptSig`
        /// the consensus rules expect, whatever the size of the redeem script.
        #[test]
        fn p2sh_multisig_spend_has_the_expected_script_sig(
            seeds in prop::collection::btree_set(any::<[u8; 32]>(), 1..=MAX_MULTISIG_KEYS),
            threshold_seed in any::<prop::sample::Index>(),
        ) {
            let Ok(secret_keys) = seeds
                .into_iter()
                .map(SecretKey::from_secret_bytes)
                .collect::<Result<Vec<_>, _>>()
            else {
                // Not every 32-byte string is a secret key.
                return Ok(());
            };
            let pubkeys = secret_keys
                .iter()
                .map(|sk| PublicKey::from_secret_key(sk).serialize())
                .collect::<Vec<_>>();
            let threshold = threshold_seed.index(pubkeys.len()) + 1;

            let redeem_script = script::Component(
                check_multisig(
                    u8::try_from(threshold).expect("at most MAX_MULTISIG_KEYS"),
                    &pubkeys.iter().map(|pk| &pk[..]).collect::<Vec<_>>(),
                    false,
                )
                .expect("a valid multisig script"),
            )
            .weaken();
            let redeem_bytes = redeem_script.to_bytes();

            let coin = TxOut::new(
                Zatoshis::const_from_u64(COIN),
                TransparentAddress::ScriptHash(hash160::hash(&redeem_bytes))
                    .script()
                    .into(),
            );
            let recipient = TransparentAddress::PublicKeyHash(hash160::hash(&pubkeys[0]));
            let fee_rule = FeeRule::standard();

            // The fee depends on the shape of the transaction but not on the output's
            // value, so it can be read from a first builder.
            let fee = spend_builder(&redeem_script, &coin, &recipient, Zatoshis::ZERO)
                .get_fee(&fee_rule)
                .expect("the fee is computable");
            let output_value = (coin.value() - fee).expect("the coin covers the fee");

            let parts = spend_builder(&redeem_script, &coin, &recipient, output_value)
                .build_for_pczt(UnwrapErr(SysRng), &fee_rule)
                .expect("the transaction balances")
                .pczt_parts;
            let pczt = Creator::build_from_parts(parts).expect("a supported transaction version");
            let pczt = IoFinalizer::new(pczt)
                .finalize_io(UnwrapErr(SysRng))
                .expect("the inputs and outputs are complete");

            // Sign with the first `threshold` keys. The signatures appear in the
            // `scriptSig` in the order of their keys in the redeem script, each followed
            // by its sighash type.
            let mut signer = Signer::new(pczt).expect("a signable PCZT");
            let sighash = signer.transparent_sighash(0).expect("the input exists");
            let mut expected = vec![OP_0];
            for sk in &secret_keys[..threshold] {
                let signature = ecdsa::sign(Message::from_digest(sighash), sk);
                signer
                    .append_transparent_signature(0, signature)
                    .expect("the key is in the redeem script");
                expected.extend(push(
                    &[&signature.serialize_der()[..], &[SIGHASH_ALL]].concat(),
                ));
            }
            expected.extend(push(&redeem_bytes));
            let pczt = signer.finish();

            let (spend_vk, output_vk) = sapling_verifying_keys();
            let tx = extract_unrecorded(pczt, (spend_vk, output_vk), None)
                .expect("the PCZT is fully signed");
            let bundle = tx.transparent_bundle().expect("the transaction has a transparent input");

            prop_assert_eq!(bundle.vin[0].script_sig().0.0.clone(), expected);
        }
    }
}
