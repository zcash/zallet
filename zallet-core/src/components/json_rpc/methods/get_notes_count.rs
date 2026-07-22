use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{InputSource, NoteFilter, WalletRead, wallet::TargetHeight};
use zcash_protocol::{ShieldedPool, value::Zatoshis};

use crate::components::{
    database::DbConnection,
    json_rpc::{
        server::LegacyCode,
        utils::{parse_as_of_height, parse_minconf},
    },
};

/// Response to a `z_getnotescount` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = GetNotesCount;

/// The number of notes in the wallet.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct GetNotesCount {
    /// The number of Sprout notes in the wallet.
    ///
    /// Always zero, because Sprout is not supported.
    sprout: u32,

    /// The number of Sapling notes in the wallet.
    sapling: u32,

    /// The number of Orchard notes in the wallet.
    orchard: u32,

    /// The number of Ironwood notes in the wallet.
    ///
    /// Ironwood (NU6.3, ZIP 2005) notes are Orchard-shaped but tracked as a
    /// distinct pool.
    ironwood: u32,
}

pub(super) const PARAM_MINCONF_DESC: &str =
    "Only include notes in transactions confirmed at least this many times.";
pub(super) const PARAM_AS_OF_HEIGHT_DESC: &str = "Execute the query as if it were run when the blockchain was at the height specified by this argument.";

pub(crate) fn call(
    wallet: &DbConnection,
    minconf: Option<u32>,
    as_of_height: Option<i64>,
) -> Response {
    let as_of_height = parse_as_of_height(as_of_height)?;
    let minconf = parse_minconf(minconf, 1, as_of_height)?;

    let chain_height = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .ok_or(LegacyCode::InWarmup.with_static("Wallet sync required"))?;

    let target_height = TargetHeight::from(as_of_height.unwrap_or(chain_height) + 1 - minconf);

    let selector = NoteFilter::ExceedsMinValue(Zatoshis::ZERO);

    let mut sapling = 0;
    let mut orchard = 0;
    let mut ironwood = 0;
    for account_id in wallet
        .get_account_ids()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
    {
        // Locked notes are still unspent notes held by the wallet, so they are counted.
        let include_locked = true;
        let account_metadata = wallet
            .get_account_metadata(account_id, &selector, target_height, &[], include_locked)
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

        if let Some(note_count) = account_metadata.note_count(ShieldedPool::Sapling) {
            sapling += note_count as u32;
        }
        if let Some(note_count) = account_metadata.note_count(ShieldedPool::Orchard) {
            orchard += note_count as u32;
        }
        if let Some(note_count) = account_metadata.note_count(ShieldedPool::Ironwood) {
            ironwood += note_count as u32;
        }
    }

    Ok(GetNotesCount {
        sprout: 0,
        sapling,
        orchard,
        ironwood,
    })
}
