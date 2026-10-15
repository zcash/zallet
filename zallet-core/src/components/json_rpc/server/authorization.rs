use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::str::FromStr;
use std::time::Duration;

use base64ct::{Base64, Encoding};
use futures::FutureExt;
use hmac::{Hmac, Mac};
use hyper::{StatusCode, header};
use jsonrpsee::{
    core::BoxError,
    server::{HttpBody, HttpRequest, HttpResponse},
};
use rand::{RngExt, rand_core::UnwrapErr, rngs::SysRng};
use secrecy::{ExposeSecret, SecretString};
#[allow(deprecated)]
use sha2::{
    Sha256,
    digest::{CtOutput, OutputSizeUser, generic_array::GenericArray},
};
use tower::Service;
use tracing::{info, warn};

use super::cookie;
use crate::{config::RpcAuthSection, fl};

type SaltedPasswordHash = CtOutput<Hmac<Sha256>>;

/// Hashes a password for the JSON-RPC interface.
///
/// The password-hashing algorithm was specified by [Bitcoin Core].
///
/// [Bitcoin Core]: https://github.com/bitcoin/bitcoin/pull/7044
fn hash_password(password: &str, salt: &str) -> SaltedPasswordHash {
    let mut h = Hmac::<Sha256>::new_from_slice(salt.as_bytes())
        .expect("cannot fail, HMAC accepts any key length");
    h.write_all(password.as_bytes())
        .expect("can write into a digester");
    h.finalize()
}

/// 401 Unauthorized response.
async fn unauthorized() -> Result<HttpResponse, BoxError> {
    HttpResponse::builder()
        .header(header::WWW_AUTHENTICATE, "Basic realm=\"jsonrpc\"")
        .status(StatusCode::UNAUTHORIZED)
        .body(HttpBody::empty())
        .map_err(BoxError::from)
}

/// A salted password hash, for authorizing access to the JSON-RPC interface.
///
/// The password-hashing algorithm was specified by [Bitcoin Core].
///
/// [Bitcoin Core]: https://github.com/bitcoin/bitcoin/pull/7044
#[derive(Clone)]
pub(crate) struct PasswordHash {
    salt: String,
    hash: SaltedPasswordHash,
}

impl FromStr for PasswordHash {
    type Err = ();

    #[allow(deprecated)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (salt, hash) = s.split_once('$').ok_or(())?;
        let hash = hex::decode(hash).map_err(|_| ())?;

        (hash.len() == Hmac::<Sha256>::output_size())
            .then(|| Self {
                salt: salt.into(),
                hash: CtOutput::new(GenericArray::clone_from_slice(hash.as_slice())),
            })
            .ok_or(())
    }
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordHash")
            .field("salt", &self.salt)
            .field("hash", &hex::encode(self.hash.clone().into_bytes()))
            .finish()
    }
}

impl fmt::Display for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = hex::encode(self.hash.clone().into_bytes());
        write!(f, "{}${hash}", self.salt)
    }
}

impl PasswordHash {
    pub(crate) fn from_bare(password: &str) -> Self {
        let salt: [u8; 16] = UnwrapErr(SysRng).random();
        let salt = hex::encode(salt);
        let hash = hash_password(password, &salt);
        Self { salt, hash }
    }

    fn check(&self, password: &str) -> bool {
        hash_password(password, &self.salt) == self.hash
    }
}

#[derive(Clone, Debug)]
pub struct Authorization<S> {
    service: S,
    users: HashMap<String, PasswordHash>,
}

impl<S> Authorization<S> {
    /// Creates a new `Authorization` with the given service.
    fn new(service: S, users: HashMap<String, PasswordHash>) -> Self {
        Self { service, users }
    }

    /// Checks whether the authorization is valid.
    fn is_authorized(&self, auth_header: &header::HeaderValue) -> bool {
        let encoded_user_pass = match auth_header
            .to_str()
            .ok()
            .and_then(|s| s.strip_prefix("Basic "))
            .and_then(|s| Base64::decode_vec(s).ok())
            .and_then(|b| String::from_utf8(b).ok())
        {
            Some(s) => SecretString::new(s),
            None => return false,
        };

        let (user, pass) = match encoded_user_pass.expose_secret().split_once(':') {
            Some(res) => res,
            None => return false,
        };

        match self.users.get(user) {
            None => false,
            Some(password) => password.check(pass),
        }
    }
}

/// Implements [`tower::Layer`] for [`Authorization`].
#[derive(Clone)]
pub struct AuthorizationLayer {
    users: HashMap<String, PasswordHash>,
}

impl AuthorizationLayer {
    /// Creates a new `AuthorizationLayer`.
    pub fn new(
        auth: Vec<RpcAuthSection>,
        cookie: Option<(String, PasswordHash)>,
    ) -> Result<Self, ()> {
        let mut using_bare_password = false;
        let mut using_pwhash = false;

        let mut users: HashMap<String, PasswordHash> = auth
            .into_iter()
            .map(|a| {
                // The cookie username is reserved for the credential that Zallet
                // generates at startup. Honouring a configured entry under that name
                // would grant long-lived access via the username that clients treat as
                // the short-lived, filesystem-protected cookie credential.
                if a.user == cookie::COOKIE_USER {
                    return Err(());
                }

                match (a.password, a.pwhash) {
                    // An empty password provides no authentication; treat it as an
                    // invalid config rather than an open RPC interface.
                    (Some(password), None) if !password.expose_secret().is_empty() => {
                        using_bare_password = true;
                        Ok((a.user, PasswordHash::from_bare(password.expose_secret())))
                    }
                    (None, Some(pwhash)) => {
                        using_pwhash = true;
                        let hash: PasswordHash = pwhash.parse()?;
                        // Reject empty passwords.
                        if hash.check("") {
                            return Err(());
                        }
                        Ok((a.user, hash))
                    }
                    _ => Err(()),
                }
            })
            .collect::<Result<_, _>>()?;

        if using_bare_password {
            info!("{}", fl!("rpc-bare-password-auth-info"));
            warn!("\n{}", fl!("rpc-bare-password-auth-warn"));
        }
        if using_pwhash {
            info!("{}", fl!("rpc-pwhash-auth-info"));
        }

        if let Some((cookie_user, cookie_hash)) = cookie {
            users.insert(cookie_user, cookie_hash);
        }

        Ok(Self { users })
    }
}

impl<S> tower::Layer<S> for AuthorizationLayer {
    type Service = Authorization<S>;

    fn layer(&self, service: S) -> Self::Service {
        Authorization::new(service, self.users.clone())
    }
}

impl<S> Service<HttpRequest<HttpBody>> for Authorization<S>
where
    S: Service<HttpRequest, Response = HttpResponse> + Clone + Send + 'static,
    S::Error: Into<BoxError> + 'static,
    S::Future: Send + 'static,
{
    type Response = HttpResponse;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: HttpRequest<HttpBody>) -> Self::Future {
        match request.headers().get(header::AUTHORIZATION) {
            None => unauthorized().boxed(),
            Some(auth_header) => {
                if self.is_authorized(auth_header) {
                    let mut service = self.service.clone();
                    async move { service.call(request).await.map_err(Into::into) }.boxed()
                } else {
                    async {
                        // Deter brute-forcing. If this results in a DoS the user really
                        // shouldn't have their RPC port exposed.
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        unauthorized().await
                    }
                    .boxed()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use hyper::header::HeaderValue;

    use super::{Authorization, AuthorizationLayer, PasswordHash};
    use crate::components::json_rpc::server::cookie;

    /// Constructs an `Authorization` with the given users and a dummy service.
    fn auth_with_users(users: HashMap<String, PasswordHash>) -> Authorization<()> {
        Authorization::new((), users)
    }

    /// Encodes credentials as a Basic auth header value.
    fn basic_auth_header(user: &str, password: &str) -> HeaderValue {
        use base64ct::{Base64, Encoding};
        let encoded = Base64::encode_string(format!("{user}:{password}").as_bytes());
        HeaderValue::from_str(&format!("Basic {encoded}")).unwrap()
    }

    #[test]
    fn empty_bare_password_is_rejected() {
        use crate::config::RpcAuthSection;

        let auth = vec![RpcAuthSection {
            user: "user1".to_string(),
            password: Some(secrecy::SecretString::new(String::new())),
            pwhash: None,
        }];
        assert!(AuthorizationLayer::new(auth, None).is_err());
    }

    /// An empty password pre-hashed into a `pwhash` entry is just as unauthenticated as a
    /// bare empty password, and must be rejected on the same grounds.
    #[test]
    fn pwhash_of_empty_password_is_rejected() {
        use crate::config::RpcAuthSection;

        let auth = vec![RpcAuthSection {
            user: "user1".to_string(),
            password: None,
            pwhash: Some(PasswordHash::from_bare("").to_string()),
        }];
        assert!(AuthorizationLayer::new(auth, None).is_err());

        let auth = vec![RpcAuthSection {
            user: "user1".to_string(),
            password: None,
            pwhash: Some(PasswordHash::from_bare("abadpassword").to_string()),
        }];
        assert!(AuthorizationLayer::new(auth, None).is_ok());
    }

    #[test]
    fn pwhash_round_trip() {
        let password = "abadpassword";
        let pwhash = PasswordHash::from_bare(password);
        assert!(pwhash.check(password));

        let pwhash_str = pwhash.to_string();
        let parsed_pwhash = pwhash_str.parse::<PasswordHash>().unwrap();
        assert!(parsed_pwhash.check(password));
    }

    #[test]
    fn cookie_user_authenticates() {
        let cookie_password = "K4b8H3nS7vJ2mQ9pR1wX5yA0cE6fG8iL";
        let mut users = HashMap::new();
        users.insert(
            cookie::COOKIE_USER.to_string(),
            PasswordHash::from_bare(cookie_password),
        );
        let auth = auth_with_users(users);
        let header = basic_auth_header(cookie::COOKIE_USER, cookie_password);
        assert!(auth.is_authorized(&header));
    }

    #[test]
    fn cookie_and_configured_user_coexist() {
        let mut users = HashMap::new();
        let password = "abadpassword";
        let cookie_password = "K4b8H3nS7vJ2mQ9pR1wX5yA0cE6fG8iL";
        users.insert("user1".to_string(), PasswordHash::from_bare(password));
        users.insert(
            cookie::COOKIE_USER.to_string(),
            PasswordHash::from_bare(cookie_password),
        );
        let auth = auth_with_users(users);
        let user_header = basic_auth_header("user1", password);
        let cookie_header = basic_auth_header(cookie::COOKIE_USER, cookie_password);
        assert!(auth.is_authorized(&user_header));
        assert!(auth.is_authorized(&cookie_header));
    }

    #[test]
    fn wrong_cookie_password_rejected() {
        let mut users = HashMap::new();
        let cookie_password = "K4b8H3nS7vJ2mQ9pR1wX5yA0cE6fG8iL";
        let wrong_cookie_password = "wrongcookiepassword";
        users.insert(
            cookie::COOKIE_USER.to_string(),
            PasswordHash::from_bare(cookie_password),
        );
        let auth = auth_with_users(users);
        let header = basic_auth_header(cookie::COOKIE_USER, wrong_cookie_password);
        assert!(!auth.is_authorized(&header));
    }

    /// The cookie username is reserved for the credential Zallet generates at startup. A
    /// config that claims it must be rejected, not silently honoured: otherwise a
    /// configured password grants access under the name that clients trust to be the
    /// short-lived, filesystem-permission-protected cookie.
    #[test]
    fn configured_cookie_user_is_rejected() {
        use crate::config::RpcAuthSection;
        use secrecy::SecretString;

        let auth = vec![RpcAuthSection {
            user: cookie::COOKIE_USER.to_string(),
            password: Some(SecretString::new("mypassword".to_string())),
            pwhash: None,
        }];
        assert!(AuthorizationLayer::new(auth, None).is_err());

        let auth = vec![RpcAuthSection {
            user: cookie::COOKIE_USER.to_string(),
            password: None,
            pwhash: Some(PasswordHash::from_bare("mypassword").to_string()),
        }];
        assert!(AuthorizationLayer::new(auth, None).is_err());
    }

    /// The reserved username is rejected even alongside valid entries, so a config cannot
    /// smuggle it in behind an otherwise-fine user list.
    #[test]
    fn configured_cookie_user_is_rejected_alongside_valid_users() {
        use crate::config::RpcAuthSection;
        use secrecy::SecretString;

        let auth = vec![
            RpcAuthSection {
                user: "user1".to_string(),
                password: Some(SecretString::new("abadpassword".to_string())),
                pwhash: None,
            },
            RpcAuthSection {
                user: cookie::COOKIE_USER.to_string(),
                password: Some(SecretString::new("mypassword".to_string())),
                pwhash: None,
            },
        ];
        assert!(AuthorizationLayer::new(auth, None).is_err());
    }

    #[cfg(feature = "rpc-cli")]
    #[test]
    fn generated_cookie_hash_validates_against_file() {
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let (user, hash, _guard) = cookie::generate_cookie(dir.path()).unwrap();
        let file_contents = cookie::read_cookie(dir.path()).unwrap();
        let password = file_contents
            .strip_prefix(&format!("{user}:"))
            .expect("cookie file should have expected prefix");
        assert!(hash.check(password));
    }
}
