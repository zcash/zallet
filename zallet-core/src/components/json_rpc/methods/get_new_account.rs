use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{WalletRead, WalletWrite};
use zcash_protocol::consensus::BlockHeight;

use crate::components::{
    chain::{Chain, ChainView},
    database::Database,
    json_rpc::{
        server::LegacyCode,
        utils::{
            ensure_seed_is_backed_up, ensure_wallet_is_unlocked, fetch_account_birthday,
            parse_seedfp_parameter, wallet_handle,
        },
    },
    keystore::{KeyStore, SeedSelectionError},
    sync::WalletDecryptorHandle,
};

/// Response to a `z_getnewaccount` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = Account;

/// Information about the new account.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct Account {
    /// The new account's UUID within this Zallet instance.
    account_uuid: String,

    /// The new account's ZIP 32 account index.
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<u64>,
}

pub(super) const PARAM_ACCOUNT_NAME_DESC: &str = "A human-readable name for the account.";
pub(super) const PARAM_SEEDFP_DESC: &str =
    "ZIP 32 seed fingerprint for the BIP 39 mnemonic phrase from which to derive the account.";

/// Birthday height for an account created now: the block after the lower of the wallet's
/// recorded height and the chain view's tip.
///
/// The two heights are read without a shared snapshot, so the lower one is the highest
/// block both have seen. The birthday must be above it: `create_account` rewinds the
/// wallet to the chain state before the birthday, and a birthday at the already-scanned
/// tip dropped the tip block and queued a rescan that only ran on the next tip change,
/// leaving `getwalletstatus` without a `wallet_tip`, hiding shielded balances and failing
/// spends until a new block arrived (#941). A new account's keys have never been handed
/// out, so no scanned block can hold its funds and nothing is lost by starting after it.
fn new_account_birthday_height(wallet_height: BlockHeight, chain_tip: BlockHeight) -> BlockHeight {
    // `BlockHeight + u32` saturates, so this cannot overflow.
    wallet_height.min(chain_tip) + 1
}

pub(crate) async fn call<C: Chain>(
    wallet: &Database,
    keystore: &KeyStore,
    chain: C,
    decryptor: &WalletDecryptorHandle,
    account_name: &str,
    seedfp: Option<&str>,
) -> Response {
    ensure_wallet_is_unlocked(keystore).await?;

    let seedfp = seedfp.map(parse_seedfp_parameter).transpose()?;

    let chain_view = chain
        .snapshot()
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    // The wallet connection is scoped to this read and released before the chain query
    // and the keystore queries below; the keystore acquires its own connection (see
    // `Database::handle`).
    let wallet_height = {
        let handle = wallet_handle(wallet).await?;
        handle
            .as_ref()
            .chain_height()
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
            .ok_or(LegacyCode::InWarmup.with_static("Wallet sync required"))?
    };

    let chain_tip = chain_view
        .tip()
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .height();

    let birthday = fetch_account_birthday(
        &chain_view,
        new_account_birthday_height(wallet_height, chain_tip),
        None,
    )
    .await?;

    let seed_fp = keystore.select_seed(seedfp).await.map_err(|e| match e {
        SeedSelectionError::Database(e) => LegacyCode::Database.with_message(e.to_string()),
        SeedSelectionError::NoSeeds => LegacyCode::Wallet
            .with_static("Wallet does not contain any seeds to generate accounts with"),
        SeedSelectionError::Ambiguous => LegacyCode::InvalidParameter
            .with_static("Wallet has more than one seed; seedfp argument must be provided"),
        SeedSelectionError::Unknown => {
            LegacyCode::InvalidParameter.with_static("seedfp does not match any seed in the wallet")
        }
    })?;

    ensure_seed_is_backed_up(keystore, &seed_fp).await?;

    let seed = keystore
        .decrypt_seed(&seed_fp)
        .await
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    // All key material is in hand; reacquire a connection for the mutation.
    let (account_id, _usk) = wallet_handle(wallet)
        .await?
        .as_mut()
        .create_account(account_name, &seed, &birthday, None)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    // Reload viewing keys so the new account is scanned without a restart (see z_importkey).
    if decryptor.reload_keys().await.is_none() {
        tracing::warn!("sync engine has shut down; new account won't be scanned until restart");
    }

    Ok(Account {
        account_uuid: account_id.expose_uuid().to_string(),
        // TODO: Should we ever set this in Zallet?
        account: None,
    })
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::BlockHeight;

    use super::new_account_birthday_height;

    /// Two heights, so the wallet or the chain view can be the one lagging.
    const LOWER_HEIGHT: BlockHeight = BlockHeight::from_u32(1_000);
    const HIGHER_HEIGHT: BlockHeight = BlockHeight::from_u32(1_010);

    #[test]
    fn birthday_is_the_block_after_a_synced_tip() {
        assert_eq!(
            new_account_birthday_height(LOWER_HEIGHT, LOWER_HEIGHT),
            LOWER_HEIGHT + 1
        );
    }

    #[test]
    fn birthday_follows_the_lower_of_wallet_and_chain_heights() {
        assert_eq!(
            new_account_birthday_height(LOWER_HEIGHT, HIGHER_HEIGHT),
            LOWER_HEIGHT + 1
        );
        assert_eq!(
            new_account_birthday_height(HIGHER_HEIGHT, LOWER_HEIGHT),
            LOWER_HEIGHT + 1
        );
    }

    #[test]
    fn birthday_is_never_at_or_below_an_already_scanned_height() {
        for wallet in [LOWER_HEIGHT, HIGHER_HEIGHT] {
            for chain in [LOWER_HEIGHT, HIGHER_HEIGHT] {
                let birthday = new_account_birthday_height(wallet, chain);
                assert!(birthday > wallet.min(chain));
            }
        }
    }

    #[test]
    fn birthday_at_the_maximum_height_does_not_overflow() {
        let max = BlockHeight::from_u32(u32::MAX);
        assert_eq!(new_account_birthday_height(max, max), max);
        assert_eq!(
            new_account_birthday_height(BlockHeight::from_u32(0), max),
            BlockHeight::from_u32(1)
        );
    }
}
