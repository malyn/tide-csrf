//! Cross-Site Request Forgery (CSRF) protection middleware for Tide.
//!
//! This crate provides middleware that helps you defend against CSRF
//! attacks. The middleware generates a CSRF cookie, adds it to your
//! response, and generates a CSRF token and makes it available to your
//! request. You can then add the CSRF token to your HTML in subsequent
//! request headers, query parameters, or form fields. The middleware
//! then verifies that the CSRF token matches the cookie, both of which
//! must be present and correct for all protected methods (by default,
//! `POST`, `PUT`, `PATCH`, and `DELETE`).
//!
//! ## Implementation Details
//!
//! As an aside, here is how this works: the cookie and CSRF token
//! inserted in the page change on every request, but the token that is
//! encrypted into those things remains the same *as long as we flow
//! through the `previous_token_value`*. That allows us to use older
//! CSRF tokens with newer cookies (and vice versa), since they all
//! contain the same internal token value.
//!
//! This is different than how ring-anti-forgery works, for example,
//! because it requires you to *also* have a session store, which is
//! where it stashes an *unencrypted* token. That exact token is the
//! CSRF token that is put into the request and compared as-is on every
//! request.
//!
//! The Rust csrf crate that we use here does not require session
//! storage. Instead, it just sends *two* tokens down to the browser:
//! one in an encrypted cookie, and another in an encrypted CSRF token.
//! Those two values must be returned on every call to the browser and
//! are decrypted in order to compare their internal token value. Both
//! the (encrypted) cookie and the (encrypted) token include a nonce, so
//! they will be different on every single web response, but, because
//! they contain the same *internal* CSRF token, any two tokens and
//! cookies can be compared against each other as equal (as long as the
//! cookie has not expired).
//!
//! ## Example
//!
//! ```rust
//! use tide_csrf::{self, CsrfRequestExt};
//!
//! # async_std::task::block_on(async {
//! let mut app = tide::new();
//!
//! app.with(tide_csrf::CsrfMiddleware::new(
//!     b"we recommend you use std::env::var(\"TIDE_SECRET\").unwrap().as_bytes() instead of a fixed value"
//! ));
//!
//! app.at("/").get(|req: tide::Request<()>| async move {
//!     Ok(format!(
//!         "CSRF token is {}; you should put that in header {}",
//!         req.csrf_token(),
//!         req.csrf_header_name()
//!     ))
//! });
//!
//! # })
//! ```

#![forbid(unsafe_code, future_incompatible)]
#![deny(
    missing_debug_implementations,
    nonstandard_style,
    missing_docs,
    unreachable_pub,
    missing_copy_implementations,
    unused_qualifications,
    clippy::unwrap_in_result,
    clippy::unwrap_used
)]

use std::collections::HashSet;
use std::time::Duration;

use csrf::{
    AesGcmCsrfProtection, CsrfCookie, CsrfProtection, CsrfToken, UnencryptedCsrfCookie,
    UnencryptedCsrfToken,
};
use data_encoding::{BASE64, BASE64URL};
use tide::{
    http::cookies::SameSite,
    http::{headers::HeaderName, Cookie, Method},
    Middleware, Next, Request, Response, StatusCode,
};

struct CsrfRequestExtData {
    csrf_token: String,
    csrf_header_name: HeaderName,
}

/// Provides access to request-level CSRF values.
pub trait CsrfRequestExt {
    /// Gets the CSRF token for inclusion in an HTTP request header,
    /// a query parameter, or a form field.
    fn csrf_token(&self) -> &str;

    /// Gets the name of the header in which to return the CSRF token,
    /// if the CSRF token is being returned in a header.
    fn csrf_header_name(&self) -> &str;
}

impl<State> CsrfRequestExt for Request<State>
where
    State: Send + Sync + 'static,
{
    fn csrf_token(&self) -> &str {
        let ext_data: &CsrfRequestExtData = self
            .ext()
            .expect("You must install CsrfMiddleware to access the CSRF token.");
        &ext_data.csrf_token
    }

    fn csrf_header_name(&self) -> &str {
        let ext_data: &CsrfRequestExtData = self
            .ext()
            .expect("You must install CsrfMiddleware to access the CSRF token.");
        ext_data.csrf_header_name.as_str()
    }
}

/// Cross-Site Request Forgery (CSRF) protection middleware.
pub struct CsrfMiddleware {
    cookie_path: String,
    cookie_name: String,
    cookie_domain: Option<String>,
    ttl: Duration,
    header_name: HeaderName,
    protected_methods: HashSet<Method>,
    protect: AesGcmCsrfProtection,
}

impl std::fmt::Debug for CsrfMiddleware {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CsrfMiddleware")
            .field("cookie_path", &self.cookie_path)
            .field("cookie_name", &self.cookie_name)
            .field("cookie_domain", &self.cookie_domain)
            .field("ttl", &self.ttl)
            .field("header_name", &self.header_name)
            .field("protected_methods", &self.protected_methods)
            .finish()
    }
}

impl CsrfMiddleware {
    /// Create a new instance.
    ///
    /// # Defaults
    ///
    /// The defaults for CsrfMiddleware are:
    /// - cookie path: `/`
    /// - cookie name: `tide.csrf`
    /// - cookie domain: None
    /// - ttl: 24 hours
    /// - header name: `X-CSRF-Token`
    /// - protected methods: `[POST, PUT, PATCH, DELETE]`
    pub fn new(secret: &[u8]) -> Self {
        let mut key = [0u8; 32];
        derive_key(secret, &mut key);

        Self {
            cookie_path: "/".into(),
            cookie_name: "tide.csrf".into(),
            cookie_domain: None,
            ttl: Duration::from_secs(24 * 60 * 60),
            header_name: "X-CSRF-Token".into(),
            protected_methods: vec![Method::Post, Method::Put, Method::Patch, Method::Delete]
                .iter()
                .cloned()
                .collect(),
            protect: AesGcmCsrfProtection::from_key(key),
        }
    }

    /// Sets the protection ttl. This will be used for both the cookie
    /// expiry and the time window over which CSRF tokens are considered
    /// valid.
    ///
    /// The default for this value is one day.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Sets the name of the HTTP header where the middleware will look
    /// for the CSRF token.
    ///
    /// Defaults to "X-CSRF-Token".
    pub fn with_header_name(mut self, header_name: impl AsRef<str>) -> Self {
        self.header_name = header_name.as_ref().into();
        self
    }

    fn build_cookie(&self, secure: bool, cookie_value: String) -> Cookie<'static> {
        let mut cookie = Cookie::build(self.cookie_name.clone(), cookie_value)
            .http_only(true)
            .same_site(SameSite::Strict)
            .path(self.cookie_path.clone())
            .secure(secure)
            .expires((std::time::SystemTime::now() + self.ttl).into())
            .finish();

        if let Some(cookie_domain) = self.cookie_domain.clone() {
            cookie.set_domain(cookie_domain);
        }

        cookie
    }

    fn generate_token(
        &self,
        existing_cookie: Option<&UnencryptedCsrfCookie>,
    ) -> (CsrfToken, CsrfCookie) {
        let existing_cookie_bytes = existing_cookie.and_then(|c| {
            let c = c.value();
            if c.len() < 64 {
                None
            } else {
                let mut buf = [0; 64];
                buf.copy_from_slice(c);
                Some(buf)
            }
        });

        self.protect
            .generate_token_pair(existing_cookie_bytes.as_ref(), self.ttl.as_secs() as i64)
            .expect("couldn't generate token/cookie pair")
    }

    fn find_csrf_cookie<State>(&self, req: &mut Request<State>) -> Option<UnencryptedCsrfCookie>
    where
        State: Clone + Send + Sync + 'static,
    {
        req.cookie(&self.cookie_name)
            .and_then(|c| BASE64.decode(c.value().as_bytes()).ok())
            .and_then(|b| self.protect.parse_cookie(&b).ok())
    }

    fn find_csrf_token<State>(&self, req: &mut Request<State>) -> Option<UnencryptedCsrfToken>
    where
        State: Clone + Send + Sync + 'static,
    {
        let header_token = self.find_csrf_token_in_header(req);

        // TODO Support finding the token in a query param.

        // TODO Support finding the token in POST body, *but* does that cause
        // us to read/consume the body? Need to investigate before we go that
        // route.

        header_token.and_then(|b| self.protect.parse_token(&b).ok())
    }

    fn find_csrf_token_in_header<State>(&self, req: &mut Request<State>) -> Option<Vec<u8>>
    where
        State: Clone + Send + Sync + 'static,
    {
        req.header(&self.header_name).and_then(|vs| {
            vs.iter()
                .find_map(|v| BASE64URL.decode(v.as_str().as_bytes()).ok())
        })
    }
}

#[tide::utils::async_trait]
impl<State> Middleware<State> for CsrfMiddleware
where
    State: Clone + Send + Sync + 'static,
{
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> tide::Result {
        // Extract the existing CSRF token and cookie.
        let existing_token = self.find_csrf_token(&mut req);
        let existing_cookie = self.find_csrf_cookie(&mut req);
        tide::log::trace!(
            "Existing token: {:?}; existing cookie: {:?}",
            existing_token,
            existing_cookie
        );

        // Is this a protected method? If so, verify the token.
        if self.protected_methods.contains(&req.method()) {
            match (existing_token, existing_cookie.as_ref()) {
                (Some(token), Some(cookie)) => {
                    if self.protect.verify_token_pair(&token, cookie) {
                        tide::log::debug!(
                            "Verified CSRF token when calling protected method {:?}",
                            req.method()
                        );
                    } else {
                        tide::log::debug!("Rejecting request for protected method {:?} due to invalid or expired CSRF token.", req.method());
                        return Ok(Response::new(StatusCode::Forbidden));
                    }
                }
                _ => {
                    tide::log::debug!(
                        "Rejecting request for protected method {:?} due to missing CSRF token.",
                        req.method()
                    );
                    return Ok(Response::new(StatusCode::Forbidden));
                }
            }
        }

        // Generate a new cookie and token (using the existing inner
        // token data if present).
        let (token, cookie) = self.generate_token(existing_cookie.as_ref());

        // Add the token to the request for use by the application.
        let secure_cookie = req.url().scheme() == "https";
        req.set_ext(CsrfRequestExtData {
            csrf_token: token.b64_url_string(),
            csrf_header_name: self.header_name.clone(),
        });

        // Call the downstream middleware.
        let mut res = next.run(req).await;

        // Add the CSRF cookie to the response.
        let cookie = self.build_cookie(secure_cookie, cookie.b64_string());
        res.insert_cookie(cookie);

        // Return the response.
        Ok(res)
    }
}

fn derive_key(secret: &[u8], key: &mut [u8; 32]) {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, secret);
    hk.expand(&[0u8; 0], key)
        .expect("Sha256 should be able to produce a 32 byte key.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tide::{
        http::headers::{COOKIE, SET_COOKIE},
        Request,
    };
    use tide_testing::{surf::Response, TideTestingExt};

    const SECRET: [u8; 32] = *b"secrets must be >= 32 bytes long";

    #[async_std::test]
    async fn middleware_exposes_csrf_request_extensions() -> tide::Result<()> {
        let mut app = tide::new();
        app.with(CsrfMiddleware::new(&SECRET));

        app.at("/").get(|req: Request<()>| async move {
            assert_ne!(req.csrf_token(), "");
            assert_eq!(req.csrf_header_name(), "x-csrf-token");
            Ok("")
        });

        let res = app.get("/").await?;
        assert_eq!(res.status(), StatusCode::Ok);

        Ok(())
    }

    #[async_std::test]
    async fn middleware_adds_csrf_cookie_sets_request_token() -> tide::Result<()> {
        let mut app = tide::new();
        app.with(CsrfMiddleware::new(&SECRET));

        app.at("/")
            .get(|req: Request<()>| async move { Ok(req.csrf_token().to_string()) });

        let mut res = app.get("/").await?;
        assert_eq!(res.status(), StatusCode::Ok);

        let csrf_token = res.body_string().await?;
        assert_ne!(csrf_token, "");

        let cookie = get_csrf_cookie(&res).expect("Expected CSRF cookie in response.");
        assert_eq!(cookie.name(), "tide.csrf");

        Ok(())
    }

    #[async_std::test]
    async fn middleware_validates_token() -> tide::Result<()> {
        let mut app = tide::new();
        app.with(CsrfMiddleware::new(&SECRET));

        app.at("/")
            .get(|req: Request<()>| async move { Ok(req.csrf_token().to_string()) })
            .post(|_| async { Ok("POST") });

        let mut res = app.get("/").await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let csrf_token = res.body_string().await?;
        let cookie = get_csrf_cookie(&res).expect("Expected CSRF cookie in response.");
        assert_eq!(cookie.name(), "tide.csrf");

        let res = app.post("/").await?;
        assert_eq!(res.status(), StatusCode::Forbidden);

        let res = app
            .post("/")
            .header(COOKIE, cookie.to_string())
            .header("X-CSRF-Token", csrf_token)
            .await?;
        assert_eq!(res.status(), StatusCode::Ok);

        Ok(())
    }

    #[async_std::test]
    async fn middleware_validates_token_in_alternate_header() -> tide::Result<()> {
        let mut app = tide::new();
        app.with(CsrfMiddleware::new(&SECRET).with_header_name("X-MyCSRF-Header"));

        app.at("/")
            .get(|req: Request<()>| async move {
                assert_eq!(req.csrf_header_name(), "x-mycsrf-header");
                Ok(req.csrf_token().to_string())
            })
            .post(|_| async { Ok("POST") });

        let mut res = app.get("/").await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let csrf_token = res.body_string().await?;
        let cookie = get_csrf_cookie(&res).expect("Expected CSRF cookie in response.");

        let res = app
            .post("/")
            .header(COOKIE, cookie.to_string())
            .header("X-MyCSRF-Header", csrf_token)
            .await?;
        assert_eq!(res.status(), StatusCode::Ok);

        Ok(())
    }

    // TODO Create some tests that show/verify how newer cookies can
    // be used with older tokens (and vice versa).

    fn get_csrf_cookie(res: &Response) -> Option<Cookie> {
        if let Some(values) = res.header(SET_COOKIE) {
            if let Some(value) = values.get(0) {
                Cookie::parse(value.to_string()).ok()
            } else {
                None
            }
        } else {
            None
        }
    }
}
