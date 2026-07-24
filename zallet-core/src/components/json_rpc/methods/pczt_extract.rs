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
use pczt::roles::spend_finalizer::SpendFinalizer;
use pczt::roles::tx_extractor::TransactionExtractor;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{WalletRead, wallet::extract_and_store_transaction_from_pczt};
use zcash_client_sqlite::ReceivedNoteId;

use super::pczt_common::{
    PROP_BACKEND_PROPOSAL_INFO, PROVING_SLOTS, circuit_version_for_branch, decode_pczt_base64,
    orchard_verifying_key, sapling_verifying_keys,
};
use super::pczt_error::PcztError;
use crate::{
    components::{database::DbHandle, json_rpc::server::LegacyCode},
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

/// Extracts a final, network-ready transaction from a completed PCZT.
///
/// The PCZT must already have all required proofs and signatures in place;
/// extraction verifies the shielded ones and fails otherwise. (Transparent
/// script signatures are checked by the network at broadcast, not here.)
pub(crate) async fn call(mut wallet: DbHandle, pczt_base64: &str) -> Response {
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

    let (tx_bytes, txid, stored): (Vec<u8>, String, bool) =
        crate::spawn_blocking!("pczt_extract", move || -> Result<_, ErrorObjectOwned> {
            if wallet_created {
                // Finalizes spends, verifies, stores the transaction in the
                // wallet database, and returns its ID.
                let txid = extract_and_store_transaction_from_pczt::<_, ReceivedNoteId>(
                    wallet.as_mut(),
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

                let mut tx_bytes = Vec::new();
                tx.write(&mut tx_bytes).map_err(|e| {
                    LegacyCode::Deserialization
                        .with_message(fl!("err-pczt-serialize-transaction", error = e.to_string()))
                })?;
                Ok((tx_bytes, txid.to_string(), true))
            } else {
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
                let tx = extractor.extract().map_err(PcztError::Extract)?;

                let mut tx_bytes = Vec::new();
                tx.write(&mut tx_bytes).map_err(|e| {
                    LegacyCode::Deserialization
                        .with_message(fl!("err-pczt-serialize-transaction", error = e.to_string()))
                })?;
                Ok((tx_bytes, tx.txid().to_string(), false))
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
