use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use secrecy::SecretVec;
use serde::Serialize;
use zcash_client_backend::data_api::{AccountBirthday, WalletRead, WalletWrite};
use zcash_client_sqlite::{AccountUuid, error::SqliteClientError};
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

/// How many birthdays `z_getnewaccount` tries before giving up.
///
/// Each attempt reads the heights afresh, so a retry only loses to the sync engine again
/// if it scans another block in the same window. On a node whose chain view sits behind
/// the wallet (briefly after a restart, or during a reorg) every attempt loses, and the
/// call fails rather than rewinding the wallet to the view's tip.
pub(super) const MAX_BIRTHDAY_ATTEMPTS: u32 = 3;

/// Outcome of [`create_account_below_scanned_tip`].
enum Creation {
    Created(AccountUuid),
    /// The wallet had scanned up to this block, at or above the chosen birthday, by the time
    /// the account was about to be created. Creating it would have rewound the wallet.
    ScannedPastBirthday(BlockHeight),
}

/// Creates the account at `birthday`, unless the wallet has already scanned the birthday
/// block.
///
/// The birthday is chosen from heights read before the keystore and chain queries, and the
/// sync engine can scan the birthday block in between. `create_account` would then rewind
/// the wallet to the state before it, dropping the scanned block exactly as in #941. The
/// check and the creation run in one wallet-database transaction, which also holds the
/// connection's write lock, so no block can land between them.
async fn create_account_below_scanned_tip(
    wallet: &Database,
    account_name: &str,
    seed: &SecretVec<u8>,
    birthday: &AccountBirthday,
) -> RpcResult<Creation> {
    wallet_handle(wallet)
        .await?
        .with_mut(|mut db_data| {
            db_data.transactionally(|wdb| -> Result<Creation, SqliteClientError> {
                let scanned_past_birthday = wdb
                    .block_max_scanned()?
                    .map(|block| block.block_height())
                    .filter(|&scanned| scanned >= birthday.height());
                if let Some(scanned) = scanned_past_birthday {
                    return Ok(Creation::ScannedPastBirthday(scanned));
                }
                let (account_id, _usk) = wdb.create_account(account_name, seed, birthday, None)?;
                Ok(Creation::Created(account_id))
            })
        })
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))
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

    // All key material is in hand before the birthday is chosen, so the window in which
    // the sync engine can scan past it spans only the treestate fetch.
    let mut attempt = 1;
    let account_id = loop {
        let chain_view = chain
            .snapshot()
            .await
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

        // The wallet connection is scoped to this read and released before the chain
        // query below; the account creation acquires its own connection.
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

        match create_account_below_scanned_tip(wallet, account_name, &seed, &birthday).await? {
            Creation::Created(account_id) => break account_id,
            Creation::ScannedPastBirthday(scanned) if attempt < MAX_BIRTHDAY_ATTEMPTS => {
                tracing::info!(
                    "Wallet scanned block {scanned} while choosing birthday {} for the new \
                     account; choosing again (attempt {attempt} of {MAX_BIRTHDAY_ATTEMPTS})",
                    birthday.height(),
                );
                attempt += 1;
            }
            Creation::ScannedPastBirthday(scanned) => {
                return Err(LegacyCode::InWarmup.with_message(format!(
                    "Wallet has scanned block {scanned}, past birthday {} chosen from chain tip \
                     {chain_tip}; retry once the node has caught up with the wallet",
                    birthday.height(),
                )));
            }
        }
    };

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
