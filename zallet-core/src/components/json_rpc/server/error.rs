//! RPC error codes & their handling.

use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};

/// Bitcoin RPC error codes
///
/// Drawn from <https://github.com/zcash/zcash/blob/99ad6fdc3a549ab510422820eea5e5ce9f60a5fd/src/rpc/protocol.h#L32-L80>.
///
/// ## Notes
///
/// - All explicit discriminants fit within `i64`.
#[derive(Default, Debug)]
pub enum LegacyCode {
    // General application defined errors
    /// `std::exception` thrown in command handling
    #[default]
    Misc = -1,
    /// Server is in safe mode, and command is not allowed in safe mode
    ForbiddenBySafeMode = -2,
    /// Unexpected type was passed as parameter
    Type = -3,
    /// Invalid address or key
    InvalidAddressOrKey = -5,
    /// Ran out of memory during operation
    OutOfMemory = -7,
    /// Invalid, missing or duplicate parameter
    InvalidParameter = -8,
    /// Database error
    Database = -20,
    /// Error parsing or validating structure in raw format
    Deserialization = -22,
    /// General error during transaction or block submission
    Verify = -25,
    /// Transaction or block was rejected by network rules
    VerifyRejected = -26,
    /// Transaction already in chain
    VerifyAlreadyInChain = -27,
    /// Client still warming up
    InWarmup = -28,

    // P2P client errors
    /// Bitcoin is not connected
    ClientNotConnected = -9,
    /// Still downloading initial blocks
    ClientInInitialDownload = -10,
    /// Node is already added
    ClientNodeAlreadyAdded = -23,
    /// Node has not been added before
    ClientNodeNotAdded = -24,
    /// Node to disconnect not found in connected nodes
    ClientNodeNotConnected = -29,
    /// Invalid IP/Subnet
    ClientInvalidIpOrSubnet = -30,

    // Wallet errors
    /// Unspecified problem with wallet (key not found etc.)
    Wallet = -4,
    /// Not enough funds in wallet or account
    WalletInsufficientFunds = -6,
    /// Accounts are unsupported
    WalletAccountsUnsupported = -11,
    /// Keypool ran out, call keypoolrefill first
    WalletKeypoolRanOut = -12,
    /// Enter the wallet passphrase with walletpassphrase first
    WalletUnlockNeeded = -13,
    /// The wallet passphrase entered was incorrect
    WalletPassphraseIncorrect = -14,
    /// Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)
    WalletWrongEncState = -15,
    /// Failed to encrypt the wallet
    WalletEncryptionFailed = -16,
    /// Wallet is already unlocked
    WalletAlreadyUnlocked = -17,
    /// User must acknowledge backup of the mnemonic seed.
    WalletBackupRequired = -18,
}

impl LegacyCode {
    /// Adds a message to this error.
    pub fn with_message(self, message: impl Into<String>) -> ErrorObjectOwned {
        ErrorObjectOwned::owned(self.into(), message, None::<()>)
    }

    /// Adds a message to this error that is a static string.
    pub fn with_static(self, message: &'static str) -> ErrorObjectOwned {
        ErrorObjectOwned::borrowed(self.into(), message, None)
    }
}

impl From<LegacyCode> for ErrorCode {
    fn from(code: LegacyCode) -> Self {
        Self::ServerError(code as i32)
    }
}

impl From<LegacyCode> for i32 {
    fn from(code: LegacyCode) -> Self {
        code as i32
    }
}
