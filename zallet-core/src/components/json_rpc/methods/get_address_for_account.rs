use std::collections::BTreeSet;

use documented::Documented;
use jsonrpsee::{
    core::{JsonValue, RpcResult},
    types::{ErrorCode as RpcErrorCode, ErrorObjectOwned},
};
use schemars::JsonSchema;
use serde::Serialize;
use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
use zcash_address::unified;
#[cfg(zallet_build = "wallet")]
use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_backend::{
    address::UnifiedAddress,
    data_api::WalletWrite,
    keys::{AddressGenerationError, ReceiverRequirement, UnifiedAddressRequest},
    wallet::Exposure,
};
use zcash_client_sqlite::{AccountUuid, error::SqliteClientError};
use zip32::DiversifierIndex;

use crate::{
    components::{
        database::{Database, DbHandle},
        json_rpc::{
            server::LegacyCode,
            unified_encoding::encode_unified_address,
            utils::{parse_account_parameter, parse_diversifier_index, wallet_handle},
        },
    },
    config::TransparentGapLimitPolicy,
};

#[cfg(zallet_build = "wallet")]
use crate::components::{json_rpc::utils::ensure_seed_is_backed_up, keystore::KeyStore};

/// Response to a `z_getaddressforaccount` RPC request.
pub(crate) type Response = RpcResult<ResultType>;
pub(crate) type ResultType = Address;

/// Information about a derived Unified Address.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct Address {
    /// The account's UUID within this Zallet instance.
    account_uuid: String,

    /// The ZIP 32 account ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    account: Option<u64>,

    /// The diversifier index specified or chosen.
    diversifier_index: u128,

    /// The receiver types that the UA contains (valid values are "p2pkh", "sapling", "orchard").
    receiver_types: Vec<String>,

    /// The unified address corresponding to the diversifier.
    address: String,
}

pub(super) const PARAM_ACCOUNT_DESC: &str =
    "Either the UUID or ZIP 32 account index of the account to derive from.";
pub(super) const PARAM_RECEIVER_TYPES_DESC: &str =
    "Receiver types to include in the derived address.";
pub(super) const PARAM_DIVERSIFIER_INDEX_DESC: &str = "A specific diversifier index to derive at.";

/// The most indices past the gap window that are tried for one request before giving up.
///
/// An index is skipped only when it has no valid Sapling diversifier, which happens
/// for about half of all indices independently. The chance that this many consecutive
/// indices are all unusable is 2^-128, so the bound is never reached in practice; it
/// exists so that the search cannot run away while holding the wallet's write lock.
const MAX_INDICES_TRIED_PAST_GAP_WINDOW: usize = 128;

pub(crate) async fn call(
    wallet: &Database,
    #[cfg(zallet_build = "wallet")] keystore: KeyStore,
    account: JsonValue,
    receiver_types: Option<Vec<String>>,
    diversifier_index: Option<u128>,
    gap_limit_policy: TransparentGapLimitPolicy,
) -> Response {
    let account_id = parse_account_parameter(
        #[cfg(zallet_build = "wallet")]
        wallet,
        #[cfg(zallet_build = "wallet")]
        &keystore,
        &account,
    )
    .await?;

    // Deriving a fresh address invites new funds into the account, so it is gated on the
    // account's seed having a confirmed backup just as account creation is.
    //
    // Since accounts can no longer be created from an unconfirmed seed at all, in practice
    // this catches new usage of accounts that already existed before that gate was added:
    // a wallet whose phrase Zallet generated, and whose operator never recorded it.
    // Accounts with no key derivation (an imported viewing key, say) are not covered by
    // any mnemonic, so there is nothing to have backed up and nothing to check.
    #[cfg(zallet_build = "wallet")]
    {
        // The wallet connection is scoped to this read and released before the backup
        // check, which queries the keystore on its own connection (see
        // `Database::handle`).
        let seed_fp = wallet_handle(wallet)
            .await?
            .as_ref()
            .get_account(account_id)
            .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
            .and_then(|account| {
                account
                    .source()
                    .key_derivation()
                    .map(|derivation| *derivation.seed_fingerprint())
            });
        if let Some(seed_fp) = seed_fp {
            ensure_seed_is_backed_up(&keystore, &seed_fp).await?;
        }
    }

    let (receiver_types, request) = match receiver_types {
        Some(receiver_types) if !receiver_types.is_empty() => {
            let mut orchard = ReceiverRequirement::Omit;
            let mut sapling = ReceiverRequirement::Omit;
            let mut p2pkh = ReceiverRequirement::Omit;
            let mut invalid_receivers = vec![];
            for receiver_type in &receiver_types {
                match receiver_type.as_str() {
                    "orchard" => orchard = ReceiverRequirement::Require,
                    "sapling" => sapling = ReceiverRequirement::Require,
                    "p2sh" => {
                        return Err(LegacyCode::Wallet.with_static(
                            "Error: P2SH addresses can not be created using this RPC method.",
                        ));
                    }
                    "p2pkh" => p2pkh = ReceiverRequirement::Require,
                    _ => invalid_receivers.push(receiver_type),
                }
            }

            if invalid_receivers.is_empty() {
                UnifiedAddressRequest::custom(orchard, sapling, p2pkh)
                    .map(|request| (receiver_types, request))
                    .map_err(|_| {
                        LegacyCode::InvalidParameter.with_static(
                            "Error: cannot generate an address containing no shielded receivers.",
                        )
                    })
            } else {
                Err(LegacyCode::InvalidParameter.with_message(format!(
                    "{:?} {}. Arguments must be “p2pkh”, “sapling”, or “orchard”",
                    // TODO: Format nicely (matching zcashd).
                    invalid_receivers,
                    if invalid_receivers.len() == 1 {
                        "is an invalid receiver type"
                    } else {
                        "are invalid receiver types"
                    }
                )))
            }
        }
        _ => {
            // zcashd default is the best and second-best shielded receiver types, and the
            // transparent (P2PKH) receiver type. That currently corresponds to all possible
            // receiver types.
            let request = UnifiedAddressRequest::unsafe_custom(
                ReceiverRequirement::Require,
                ReceiverRequirement::Require,
                ReceiverRequirement::Require,
            );
            Ok((
                vec!["orchard".into(), "sapling".into(), "p2pkh".into()],
                request,
            ))
        }
    }?;

    let diversifier_index = diversifier_index.map(parse_diversifier_index).transpose()?;

    // The checks above are complete; reacquire a connection to derive the address.
    let mut wallet = wallet_handle(wallet).await?;

    let (address, diversifier_index) = if let Some(diversifier_index) = diversifier_index {
        match wallet
            .as_mut()
            .get_address_for_index(account_id, diversifier_index, request)
            .map_err(|e| map_sqlite_error(e, &account))?
        {
            Some(address) => Ok((address, diversifier_index)),
            // zcash_client_sqlite only returns `Ok(None)` if the diversifier index is
            // invalid for one of the requested receiver types.
            None => Err(LegacyCode::Wallet.with_message(format!(
                "Error: diversifier index {} cannot generate an address with the requested receivers.",
                u128::from(diversifier_index),
            ))),
        }
    } else {
        match (
            wallet
                .as_mut()
                .get_next_available_address(account_id, request),
            gap_limit_policy,
        ) {
            (
                Err(SqliteClientError::ReachedGapLimit(TransparentKeyScope::EXTERNAL, window_end)),
                TransparentGapLimitPolicy::IssuePast,
            ) => {
                let issued = issue_past_gap_window(&wallet, account_id, request, window_end)
                    .map_err(|e| map_sqlite_error(e, &account))?;
                match issued {
                    Some((address, diversifier_index)) => {
                        tracing::warn!(
                            "Issued an address for account {} at diversifier index {}, past the \
                             transparent gap limit. Funds sent to its transparent receiver will \
                             not be found by recovery from the mnemonic phrase alone.",
                            account_id.expose_uuid(),
                            u128::from(diversifier_index),
                        );
                        Ok((address, diversifier_index))
                    }
                    None => Err(LegacyCode::Wallet.with_message(format!(
                        "Error: no address with the requested receivers could be generated in \
                         the {MAX_INDICES_TRIED_PAST_GAP_WINDOW} unused indices from index \
                         {window_end}.",
                    ))),
                }
            }
            (result, _) => result
                .map_err(|e| map_sqlite_error(e, &account))?
                // This would be a race condition between this and account deletion.
                .ok_or(RpcErrorCode::InternalError.into()),
        }
    }?;

    // Only include `account` in the response if it was provided in the request. We rely
    // on the checks performed in `parse_account_parameter`.
    let account = match account {
        JsonValue::Number(n) => n.as_u64(),
        _ => None,
    };

    Ok(Address {
        account_uuid: account_id.expose_uuid().to_string(),
        account,
        diversifier_index: diversifier_index.into(),
        receiver_types,
        address: encode_unified_address(&address, wallet.params()),
    })
}

/// Issues the first unused address at or after `window_end`, the index one past the end
/// of the account's transparent gap window.
///
/// `get_next_available_address` only reserves indices inside the gap window, but an
/// explicit index outside it can be derived and is watched like any other. This picks
/// that index for the caller, so issuance stays sequential.
///
/// The read of the issued indices and the write that marks the chosen one as issued
/// share a transaction, so two concurrent requests cannot be given the same address.
///
/// Returns `Ok(None)` if none of the first [`MAX_INDICES_TRIED_PAST_GAP_WINDOW`] unused
/// indices can produce an address satisfying `request`.
fn issue_past_gap_window(
    wallet: &DbHandle,
    account_id: AccountUuid,
    request: UnifiedAddressRequest,
    window_end: u32,
) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, SqliteClientError> {
    wallet.with_mut(|mut db_data| {
        db_data.transactionally(|wdb| {
            let issued = wdb
                .get_transparent_receivers(account_id, false, false)?
                .values()
                .filter(|meta| meta.scope() == Some(TransparentKeyScope::EXTERNAL))
                .filter(|meta| matches!(meta.exposure(), Exposure::Exposed { .. }))
                .filter_map(|meta| meta.address_index())
                .collect::<BTreeSet<_>>();

            for index in
                unissued_indices_from(window_end, &issued).take(MAX_INDICES_TRIED_PAST_GAP_WINDOW)
            {
                let diversifier_index = DiversifierIndex::from(index.index());
                // `Ok(None)` means this index cannot satisfy the request, and is returned
                // before anything is written.
                if let Some(address) =
                    wdb.get_address_for_index(account_id, diversifier_index, request)?
                {
                    return Ok(Some((address, diversifier_index)));
                }
            }

            Ok(None)
        })
    })
}

/// The transparent child indices from `start` upward that are not in `issued`, in
/// increasing order.
///
/// Empty if `start` is beyond the non-hardened child index range.
fn unissued_indices_from(
    start: u32,
    issued: &BTreeSet<NonHardenedChildIndex>,
) -> impl Iterator<Item = NonHardenedChildIndex> + '_ {
    (start..=NonHardenedChildIndex::MAX.index())
        .filter_map(NonHardenedChildIndex::from_index)
        .filter(|index| !issued.contains(index))
}

fn map_address_generation_error(
    e: AddressGenerationError,
    account: &JsonValue,
) -> ErrorObjectOwned {
    match e {
        AddressGenerationError::InvalidTransparentChildIndex(diversifier_index) => {
            LegacyCode::Wallet.with_message(format!(
                "Error: diversifier index {} cannot generate an address with a transparent receiver.",
                u128::from(diversifier_index),
            ))
        }
        AddressGenerationError::InvalidSaplingDiversifierIndex(diversifier_index) => {
            LegacyCode::Wallet.with_message(format!(
                "Error: diversifier index {} cannot generate an address with a Sapling receiver.",
                u128::from(diversifier_index),
            ))
        }
        AddressGenerationError::DiversifierSpaceExhausted => LegacyCode::Wallet.with_static(
            "Error: ran out of diversifier indices. Generate a new account with z_getnewaccount"
        ),
        AddressGenerationError::ReceiverTypeNotSupported(typecode) => match typecode {
            unified::Typecode::P2SH =>  LegacyCode::Wallet.with_static(
                "Error: P2SH addresses can not be created using this RPC method.",
            ),
            _ => LegacyCode::Wallet.with_message(format!(
                "Error: receiver type {typecode:?} is not supported.",
            ))
        }
        AddressGenerationError::KeyNotAvailable(typecode) => {
            LegacyCode::Wallet.with_message(format!(
                "Error: account {account} cannot generate a receiver component with type {typecode:?}.",
            ))
        }
        AddressGenerationError::NoSatisfiableReceiver => {
            LegacyCode::Wallet.with_static(
                "Error: cannot generate an address containing no shielded receivers."
            )
        }
        AddressGenerationError::UnsupportedTransparentKeyScope(s) => {
            LegacyCode::Wallet.with_message(format!(
                "Error: Address generation is not supported for transparent key scope {s:?}", 
            ))
        }
        AddressGenerationError::Bip32DerivationError(e) => {
            LegacyCode::Wallet.with_message(format!(
                "An error occurred in BIP 32 address derivation: {e}"
            ))
        }
    }
}

fn map_sqlite_error(e: SqliteClientError, account: &JsonValue) -> ErrorObjectOwned {
    match e {
        SqliteClientError::TransparentDerivation(error) => LegacyCode::Wallet.with_message(format!(
            "Error: failed to derive a transparent component: {error}",
        )),
        SqliteClientError::AddressGeneration(e) => map_address_generation_error(e, account),
        SqliteClientError::AccountUnknown => LegacyCode::Wallet.with_message(format!(
            "Error: account {account} has not been generated by z_getnewaccount."
        )),
        SqliteClientError::ChainHeightUnknown => LegacyCode::Wallet.with_static(
            "Error: chain height is unknown. Wait for syncing to progress and then try again."
        ),
        SqliteClientError::ReachedGapLimit(_, index) => LegacyCode::Wallet.with_message(format!(
            "Error: reached the transparent gap limit while attempting to generate a new address at index {index}. \
             Fund an address that was already issued, request a specific diversifier index, \
             or set `rpc.issue_past_transparent_gap_limit` in the Zallet config.",
        )),
        SqliteClientError::DiversifierIndexReuse(diversifier_index, _) => {
            LegacyCode::Wallet.with_message(format!(
                "Error: address at diversifier index {} was already generated with different receiver types.",
                u128::from(diversifier_index),
            ))
        }
        _ => LegacyCode::Database.with_message(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use jsonrpsee::core::JsonValue;
    use proptest::prelude::*;
    use transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
    use zcash_client_sqlite::error::SqliteClientError;

    use super::{map_sqlite_error, unissued_indices_from};

    /// One past the end of a fresh account's gap window.
    const WINDOW_END: u32 = 10;

    /// How many candidates the tests look at. Arbitrary, but more than the issued
    /// indices any test places after [`WINDOW_END`].
    const CANDIDATES: usize = 8;

    fn indices(raw: impl IntoIterator<Item = u32>) -> BTreeSet<NonHardenedChildIndex> {
        raw.into_iter()
            .map(|i| NonHardenedChildIndex::from_index(i).expect("in range"))
            .collect()
    }

    fn candidates(start: u32, issued: &BTreeSet<NonHardenedChildIndex>) -> Vec<u32> {
        unissued_indices_from(start, issued)
            .take(CANDIDATES)
            .map(|index| index.index())
            .collect()
    }

    #[test]
    fn candidates_start_at_the_window_end_when_nothing_past_it_is_issued() {
        assert_eq!(
            candidates(WINDOW_END, &BTreeSet::new()),
            (WINDOW_END..).take(CANDIDATES).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn indices_issued_inside_the_window_do_not_affect_the_candidates() {
        assert_eq!(
            candidates(WINDOW_END, &indices(0..WINDOW_END)),
            candidates(WINDOW_END, &BTreeSet::new()),
        );
    }

    #[test]
    fn candidates_skip_issued_indices_and_fill_the_holes_between_them() {
        // Sequential issuance has reached two past the window, and one further index was
        // issued explicitly.
        let explicit = WINDOW_END + 4;
        let issued = indices([WINDOW_END, WINDOW_END + 1, explicit]);

        let expected = (WINDOW_END + 2..)
            .filter(|&i| i != explicit)
            .take(CANDIDATES)
            .collect::<Vec<_>>();
        assert_eq!(candidates(WINDOW_END, &issued), expected);
    }

    #[test]
    fn candidates_stop_at_the_last_non_hardened_index() {
        let max = NonHardenedChildIndex::MAX.index();

        assert_eq!(candidates(max, &BTreeSet::new()), vec![max]);
        assert_eq!(candidates(max, &indices([max])), Vec::<u32>::new());
        // A window end one past the range, as reported for a gap window that already
        // reaches the end of it.
        assert_eq!(candidates(max + 1, &BTreeSet::new()), Vec::<u32>::new());
    }

    proptest! {
        #[test]
        fn candidates_are_exactly_the_unissued_indices_in_order(
            start in 0..=NonHardenedChildIndex::MAX.index(),
            issued_offsets in prop::collection::btree_set(0u32..64, 0..32),
        ) {
            let issued = indices(
                issued_offsets
                    .iter()
                    .filter_map(|offset| start.checked_add(*offset))
                    .filter(|i| *i <= NonHardenedChildIndex::MAX.index()),
            );
            let found = candidates(start, &issued);

            let expected = (start..=NonHardenedChildIndex::MAX.index())
                .filter(|i| !issued.iter().any(|index| index.index() == *i))
                .take(CANDIDATES)
                .collect::<Vec<_>>();
            prop_assert_eq!(found, expected);
        }
    }

    #[test]
    fn gap_limit_error_reports_the_index_and_the_ways_out() {
        let error = map_sqlite_error(
            SqliteClientError::ReachedGapLimit(TransparentKeyScope::EXTERNAL, WINDOW_END),
            &JsonValue::from(0),
        );

        assert_eq!(
            error.message(),
            format!(
                "Error: reached the transparent gap limit while attempting to generate a new \
                 address at index {WINDOW_END}. Fund an address that was already issued, \
                 request a specific diversifier index, or set \
                 `rpc.issue_past_transparent_gap_limit` in the Zallet config.",
            ),
        );
    }
}
