//! Cross-Site Request Forgery (CSRF) protection middleware for Tide.
//!
//! This crate provides middleware that helps you defend against CSRF
//! attacks. The middleware generates a CSRF cookie and adds it to your
//! Tide response, and then generates a CSRF token and makes it
//! available to your Tide request. In your HTML, you then arrange for
//! the CSRF token to be returned to the server on subsequent requests,
//! either in a request header, a query parameter, or a form field. The
//! middleware then verifies that a CSRF token is present and valid
//! whenever a request is received for a protected method.
//!
//! ## Protected Methods
//!
//! By default, this middleware protects only those HTTP methods that
//! might mutate state on the server. Those "unsafe" methods are `POST`,
//! `PUT`, `PATCH`, and `DELETE`. The remaining methods -- `GET`,
//! `HEAD`, etc. -- are *not* protected by default. This limits the
//! performance impact of the middleware on your application.
//!
//! However, if your application *does* mutate state in those "safe"
//! methods then you need to [set the list of protected
//! methods](CsrfMiddleware::with_protected_methods) to include those
//! other methods.
//!
//! Note that protecting `GET` may create a "chicken and egg" situation
//! where you have no way to return the CSRF cookie and token to a
//! caller for them to return back to you in a subsequent request! In
//! general, the default list of methods is the correct one and you
//! should ensure that the "safe" methods are in fact truly safe and do
//! not perform any mutations.
//!
//! ## Performance Considerations
//!
//! This middleware adds a CSRF cookie to every request and looks for a
//! matching CSRF token when processing a request for a protected
//! method. The CSRF token can be returned in an HTTP header, the URL
//! query string, or an `application/x-www-form-urlencoded` form body.
//! The token is searched for in that order and the search will be
//! terminated as soon as the token is found.
//!
//! The most efficient place to search for the token is in an HTTP
//! header and that mechanism should be preferred if you have the
//! ability to set headers in the request. The query string is a good
//! option if you cannot set HTTP headers.
//!
//! Using form fields is the least efficient way to return the CSRF
//! token because the middleware has to read and deserialize the entire
//! request body in order to see if the token is present, and then make
//! a full, in-memory copy of the body available to your application.
//! Tide request bodies are normally streamed to the application, so
//! performing this extra deserialization and memory copy step is quite
//! expensive relative to the normal request flow.
//!
//! For this reason, the middleware searches the form fields last *and*
//! only considers `application/x-www-form-urlencoded` requests;
//! `multipart/form-data` bodies, which may contain large binary
//! payloads, are *not* searched. If you need to protect
//! `multipart/form-data` requests then you should return the CSRF token
//! in an HTTP header or the query string.
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
//! // This is an unprotected method and does not require a CSRF token
//! // (but will set the CSRF cookie).
//! app.at("/").get(|req: tide::Request<()>| async move {
//!    // Note that here we are simply returning the token in a string, but
//!    // in a real application you need to arrange for the token to appear
//!    // in the request to the server.
//!    Ok(format!(
//!        "CSRF token is {}; you should return that in header {}, or query param {}, or a form field named {}",
//!        req.csrf_token(),
//!        req.csrf_header_name(),
//!        req.csrf_query_param(),
//!        req.csrf_field_name()
//!    ))
//! });
//!
//! // This is a protected method and will only allow the request to
//! // make it to the handler if the CSRF token is present in the
//! // request. Otherwise an HTTP status of `Forbidden` will be
//! // returned and the handler will *not* be called.
//! app.at("/").post(|req: tide::Request<()>| async move {
//!    Ok("Getting this far means that the CSRF token was present in the request.")
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
    http::{cookies::SameSite, mime},
    http::{headers::HeaderName, Cookie, Method},
    Body, Middleware, Next, Request, Response, StatusCode,
};

struct CsrfRequestExtData {
    csrf_token: String,
    csrf_header_name: HeaderName,
    csrf_query_param: String,
    csrf_field_name: String,
}

/// Provides access to request-level CSRF values.
pub trait CsrfRequestExt {
    /// Gets the CSRF token for inclusion in an HTTP request header,
    /// a query parameter, or a form field.
    fn csrf_token(&self) -> &str;

    /// Gets the name of the header in which to return the CSRF token,
    /// if the CSRF token is being returned in a header.
    fn csrf_header_name(&self) -> &str;

    /// Gets the name of the query param in which to return the CSRF
    /// token, if the CSRF token is being returned in a query param.
    fn csrf_query_param(&self) -> &str;

    /// Gets the name of the form field in which to return the CSRF
    /// token, if the CSRF token is being returned in a form field.
    fn csrf_field_name(&self) -> &str;
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

    fn csrf_query_param(&self) -> &str {
        let ext_data: &CsrfRequestExtData = self
            .ext()
            .expect("You must install CsrfMiddleware to access the CSRF token.");
        ext_data.csrf_query_param.as_str()
    }

    fn csrf_field_name(&self) -> &str {
        let ext_data: &CsrfRequestExtData = self
            .ext()
            .expect("You must install CsrfMiddleware to access the CSRF token.");
        ext_data.csrf_field_name.as_str()
    }
}

/// Cross-Site Request Forgery (CSRF) protection middleware.
pub struct CsrfMiddleware {
    cookie_path: String,
    cookie_name: String,
    cookie_domain: Option<String>,
    ttl: Duration,
    header_name: HeaderName,
    query_param: String,
    form_field: String,
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
            .field("query_param", &self.query_param)
            .field("form_field", &self.form_field)
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
    /// - query param: `csrf-token`
    /// - form field: `csrf-token`
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
            query_param: "csrf-token".into(),
            form_field: "csrf-token".into(),
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

    /// Sets the name of the query parameter where the middleware will
    /// look for the CSRF token.
    ///
    /// Defaults to "csrf-token".
    pub fn with_query_param(mut self, query_param: impl AsRef<str>) -> Self {
        self.query_param = query_param.as_ref().into();
        self
    }

    /// Sets the name of the form field where the middleware will look
    /// for the CSRF token.
    ///
    /// Defaults to "csrf-token".
    pub fn with_form_field(mut self, form_field: impl AsRef<str>) -> Self {
        self.form_field = form_field.as_ref().into();
        self
    }

    /// Sets the list of methods that will be protected by this
    /// middleware
    ///
    /// Defaults to `[POST, PUT, PATCH, DELETE]`
    pub fn with_protected_methods(mut self, methods: &[Method]) -> Self {
        self.protected_methods = methods.iter().cloned().collect();
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

    fn find_csrf_cookie<State>(&self, req: &Request<State>) -> Option<UnencryptedCsrfCookie>
    where
        State: Clone + Send + Sync + 'static,
    {
        req.cookie(&self.cookie_name)
            .and_then(|c| BASE64.decode(c.value().as_bytes()).ok())
            .and_then(|b| self.protect.parse_cookie(&b).ok())
    }

    async fn find_csrf_token<State>(
        &self,
        req: &mut Request<State>,
    ) -> Result<Option<UnencryptedCsrfToken>, tide::Error>
    where
        State: Clone + Send + Sync + 'static,
    {
        // A bit of a strange flow here (with an early exit as well),
        // because we do not want to do the expensive parsing (form,
        // body specifically) if we find a CSRF token in an earlier
        // location. And we can't use `or_else` chaining since the
        // function that searches through the form body is async. Note
        // that if parsing the body fails then we want to return an
        // InternalServerError, hence the `?`. This is not the same as
        // what we will do later, which is convert failures to *parse* a
        // found CSRF token into Forbidden responses.
        let csrf_token = if let Some(csrf_token) = self.find_csrf_token_in_header(req) {
            csrf_token
        } else if let Some(csrf_token) = self.find_csrf_token_in_query(req) {
            csrf_token
        } else if let Some(csrf_token) = self.find_csrf_token_in_form(req).await? {
            csrf_token
        } else {
            return Ok(None);
        };

        Ok(Some(self.protect.parse_token(&csrf_token).map_err(
            |err| tide::Error::new(StatusCode::Forbidden, err),
        )?))
    }

    fn find_csrf_token_in_header<State>(&self, req: &Request<State>) -> Option<Vec<u8>>
    where
        State: Clone + Send + Sync + 'static,
    {
        req.header(&self.header_name).and_then(|vs| {
            vs.iter()
                .find_map(|v| BASE64URL.decode(v.as_str().as_bytes()).ok())
        })
    }

    fn find_csrf_token_in_query<State>(&self, req: &Request<State>) -> Option<Vec<u8>>
    where
        State: Clone + Send + Sync + 'static,
    {
        req.url().query_pairs().find_map(|(key, value)| {
            if key == self.query_param {
                BASE64URL.decode(value.as_bytes()).ok()
            } else {
                None
            }
        })
    }

    async fn find_csrf_token_in_form<State>(
        &self,
        req: &mut Request<State>,
    ) -> Result<Option<Vec<u8>>, tide::Error>
    where
        State: Clone + Send + Sync + 'static,
    {
        // We only try to look for the CSRF token in a form field if the
        // body is in fact a form.
        if req.content_type() != Some(mime::FORM) {
            return Ok(None);
        }

        // Get a copy of the body as a byte array. Note that the request
        // is essentially unusable if this fails and we return an error
        // (since the body has been taken and not replaced).
        let body = req.take_body().into_bytes().await?;

        // Try to find the CSRF token. This could fail for multiple
        // reasons (such as an inability to parse the body as a form
        // body), but we convert all of those failures to a `None`
        // result since we do not want to block the request at this
        // point. The caller will decide if/how to block the request
        // based on missing/mismatched CSRF tokens. This is unlike what
        // happens if we cannot read the body at all (above), where our
        // only option is to completely fail the request.
        //
        // Note that an important subtlety in this function is that we
        // *must* put the body back after we try to find the CSRF token,
        // so we cannot fail directly out of this decoding step, but
        // must instead compute the result, put the body back into the
        // request, then return whatever resulted was computed.
        let csrf_token = serde_urlencoded::from_bytes::<Vec<(String, String)>>(&body)
            .unwrap_or_default()
            .into_iter()
            .find_map(|(key, value)| {
                if key == self.form_field {
                    BASE64URL.decode(value.as_bytes()).ok()
                } else {
                    None
                }
            });

        // Put a new body, backed by our copied byte array, into the
        // request.
        req.set_body(Body::from_bytes(body));

        // Return the CSRF token (which may be None, if we didn't actually
        // find a CSRF token in the form).
        Ok(csrf_token)
    }
}

#[tide::utils::async_trait]
impl<State> Middleware<State> for CsrfMiddleware
where
    State: Clone + Send + Sync + 'static,
{
    async fn handle(&self, mut req: Request<State>, next: Next<'_, State>) -> tide::Result {
        // We always begin by trying to find the existing CSRF cookie,
        // even if we do not need to protect this method. A new token is
        // generated on every request *based on the encrypted key in the
        // cookie* and so we always want to find the existing cookie in
        // order to generate a token that uses the same underlying key.
        let existing_cookie = self.find_csrf_cookie(&req);

        // Is this a protected method? If so, we need to find the token
        // and verify it against the cookie before we can allow the
        // request.
        if self.protected_methods.contains(&req.method()) {
            if let Some(cookie) = &existing_cookie {
                if let Some(token) = self.find_csrf_token(&mut req).await? {
                    if self.protect.verify_token_pair(&token, cookie) {
                        tide::log::debug!("Verified CSRF token.");
                    } else {
                        tide::log::debug!(
                            "Rejecting request due to invalid or expired CSRF token."
                        );
                        return Ok(Response::new(StatusCode::Forbidden));
                    }
                } else {
                    tide::log::debug!("Rejecting request due to missing CSRF token.",);
                    return Ok(Response::new(StatusCode::Forbidden));
                }
            } else {
                tide::log::debug!("Rejecting request due to missing CSRF cookie.",);
                return Ok(Response::new(StatusCode::Forbidden));
            }
        }

        // Generate a new cookie and token (using the existing cookie if
        // present).
        let (token, cookie) = self.generate_token(existing_cookie.as_ref());

        // Add the token to the request for use by the application.
        let secure_cookie = req.url().scheme() == "https";
        req.set_ext(CsrfRequestExtData {
            csrf_token: token.b64_url_string(),
            csrf_header_name: self.header_name.clone(),
            csrf_query_param: self.query_param.clone(),
            csrf_field_name: self.form_field.clone(),
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
    async fn middleware_validates_token_in_header() -> tide::Result<()> {
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

        let mut res = app
            .post("/")
            .header(COOKIE, cookie.to_string())
            .header("X-CSRF-Token", csrf_token)
            .await?;
        assert_eq!(res.status(), StatusCode::Ok);
        assert_eq!(res.body_string().await?, "POST");

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

        let mut res = app
            .post("/")
            .header(COOKIE, cookie.to_string())
            .header("X-MyCSRF-Header", csrf_token)
            .await?;
        assert_eq!(res.status(), StatusCode::Ok);
        assert_eq!(res.body_string().await?, "POST");

        Ok(())
    }

    #[async_std::test]
    async fn middleware_validates_token_in_alternate_query() -> tide::Result<()> {
        // tide::log::with_level(tide::log::LevelFilter::Trace);
        let mut app = tide::new();
        app.with(CsrfMiddleware::new(&SECRET).with_query_param("my-csrf-token"));

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

        let mut res = app
            .post(format!("/?a=1&my-csrf-token={}&b=2", csrf_token))
            .header(COOKIE, cookie.to_string())
            .await?;
        assert_eq!(res.status(), StatusCode::Ok);
        assert_eq!(res.body_string().await?, "POST");

        Ok(())
    }

    #[async_std::test]
    async fn middleware_validates_token_in_query() -> tide::Result<()> {
        // tide::log::with_level(tide::log::LevelFilter::Trace);
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

        let mut res = app
            .post(format!("/?a=1&csrf-token={}&b=2", csrf_token))
            .header(COOKIE, cookie.to_string())
            .await?;
        assert_eq!(res.status(), StatusCode::Ok);
        assert_eq!(res.body_string().await?, "POST");

        Ok(())
    }

    #[async_std::test]
    async fn middleware_validates_token_in_form() -> tide::Result<()> {
        // tide::log::with_level(tide::log::LevelFilter::Trace);
        let mut app = tide::new();
        app.with(CsrfMiddleware::new(&SECRET));

        app.at("/")
            .get(|req: Request<()>| async move { Ok(req.csrf_token().to_string()) })
            .post(|mut req: Request<()>| async move {
                // Deserialize our part of the form in order to verify that
                // the CsrfMiddleware does not break form parsing since it
                // also had to parse the form in order to find its CSRF field.
                #[derive(serde::Deserialize)]
                struct Form {
                    a: String,
                    b: i32,
                }
                let form: Form = req.body_form().await?;
                assert_eq!(form.a, "1");
                assert_eq!(form.b, 2);

                Ok("POST")
            });

        let mut res = app.get("/").await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let csrf_token = res.body_string().await?;
        let cookie = get_csrf_cookie(&res).expect("Expected CSRF cookie in response.");
        assert_eq!(cookie.name(), "tide.csrf");

        let res = app.post("/").await?;
        assert_eq!(res.status(), StatusCode::Forbidden);

        let mut res = app
            .post("/")
            .header(COOKIE, cookie.to_string())
            .content_type("application/x-www-form-urlencoded")
            .body(format!("a=1&csrf-token={}&b=2", csrf_token))
            .await?;
        assert_eq!(res.status(), StatusCode::Ok);
        assert_eq!(res.body_string().await?, "POST");

        Ok(())
    }

    #[async_std::test]
    async fn middleware_ignores_non_form_bodies() -> tide::Result<()> {
        // tide::log::with_level(tide::log::LevelFilter::Trace);
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

        // Include the CSRF token in what *looks* like a form body, but
        // the Content-Type is `text/html` and so the middleware will
        // ignore the body.
        let res = app
            .post("/")
            .header(COOKIE, cookie.to_string())
            .content_type("text/html")
            .body(format!("a=1&csrf-token={}&b=2", csrf_token))
            .await?;
        assert_eq!(res.status(), StatusCode::Forbidden);

        Ok(())
    }

    #[async_std::test]
    async fn middleware_allows_different_generation_cookies_and_tokens() -> tide::Result<()> {
        let mut app = tide::new();
        app.with(CsrfMiddleware::new(&SECRET));

        app.at("/")
            .get(|req: Request<()>| async move { Ok(req.csrf_token().to_string()) })
            .post(|req: Request<()>| async move { Ok(req.csrf_token().to_string()) });

        let mut res = app.get("/").await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let csrf_token = res.body_string().await?;
        let cookie = get_csrf_cookie(&res).expect("Expected CSRF cookie in response.");
        assert_eq!(cookie.name(), "tide.csrf");

        let res = app.post("/").await?;
        assert_eq!(res.status(), StatusCode::Forbidden);

        // Send a valid CSRF token and verify that we get back a
        // *different* token *and* cookie (which is how the `csrf` crate
        // works; each response generates a different token and cookie,
        // but all related -- part of the same request/response flow --
        // tokens and cookies are compatible with each other until they
        // expire).
        let mut res = app
            .post("/")
            .header(COOKIE, cookie.to_string())
            .header("X-CSRF-Token", &csrf_token)
            .await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let new_csrf_token = res.body_string().await?;
        assert_ne!(new_csrf_token, csrf_token);
        let new_cookie = get_csrf_cookie(&res).expect("Expected CSRF cookie in response.");
        assert_eq!(new_cookie.name(), "tide.csrf");
        assert_ne!(new_cookie.to_string(), cookie.to_string());

        // Now send another request with the *first* token and the
        // *second* cookie and verify that the older token still works.
        // (because the token hasn't expired yet, and all unexpired
        // tokens are compatible with all related cookies).
        let res = app
            .post("/")
            .header(COOKIE, new_cookie.to_string())
            .header("X-CSRF-Token", csrf_token)
            .await?;
        assert_eq!(res.status(), StatusCode::Ok);

        // Finally, one more check that does the opposite of what we
        // just did: a new token with an old cookie.
        let res = app
            .post("/")
            .header(COOKIE, cookie.to_string())
            .header("X-CSRF-Token", new_csrf_token)
            .await?;
        assert_eq!(res.status(), StatusCode::Ok);

        Ok(())
    }

    #[async_std::test]
    async fn middleware_rejects_short_token() -> tide::Result<()> {
        // tide::log::with_level(tide::log::LevelFilter::Trace);
        let mut app = tide::new();
        app.with(CsrfMiddleware::new(&SECRET));

        app.at("/")
            .get(|req: Request<()>| async move { Ok(req.csrf_token().to_string()) })
            .post(|_| async { Ok("POST") });

        let res = app.get("/").await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let cookie = get_csrf_cookie(&res).expect("Expected CSRF cookie in response.");
        assert_eq!(cookie.name(), "tide.csrf");

        let res = app.post("/").await?;
        assert_eq!(res.status(), StatusCode::Forbidden);

        // Send a CSRF token that is not a token (instead, it is the
        // Base64 string "hello") and verify that we get a Forbidden
        // response (and not a server error or anything like that, since
        // the server is operating fine, it is the request that we are
        // rejecting).
        let res = app
            .post("/")
            .header(COOKIE, cookie.to_string())
            .header("X-CSRF-Token", "aGVsbG8=")
            .await?;
        assert_eq!(res.status(), StatusCode::Forbidden);

        Ok(())
    }

    #[async_std::test]
    async fn middleware_rejects_invalid_base64_token() -> tide::Result<()> {
        // tide::log::with_level(tide::log::LevelFilter::Trace);
        let mut app = tide::new();
        app.with(CsrfMiddleware::new(&SECRET));

        app.at("/")
            .get(|req: Request<()>| async move { Ok(req.csrf_token().to_string()) })
            .post(|_| async { Ok("POST") });

        let res = app.get("/").await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let cookie = get_csrf_cookie(&res).expect("Expected CSRF cookie in response.");
        assert_eq!(cookie.name(), "tide.csrf");

        let res = app.post("/").await?;
        assert_eq!(res.status(), StatusCode::Forbidden);

        // Send a corrupt Base64 string as the CSRF token and verify
        // that we get a Forbidden response (and not a server error or
        // anything like that, since the server is operating fine, it is
        // the request that we are rejecting).
        let res = app
            .post("/")
            .header(COOKIE, cookie.to_string())
            .header("X-CSRF-Token", "aGVsbG8")
            .await?;
        assert_eq!(res.status(), StatusCode::Forbidden);

        Ok(())
    }

    #[async_std::test]
    async fn middleware_rejects_mismatched_token() -> tide::Result<()> {
        let mut app = tide::new();
        app.with(CsrfMiddleware::new(&SECRET));

        app.at("/")
            .get(|req: Request<()>| async move { Ok(req.csrf_token().to_string()) })
            .post(|_| async { Ok("POST") });

        // Make two requests, keep the token from the first and the
        // cookie from the second. This ensures that we have a
        // validly-formatted token, but one that will be rejected if
        // provided with the wrong cookie.
        let mut res = app.get("/").await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let csrf_token = res.body_string().await?;

        let res = app.get("/").await?;
        assert_eq!(res.status(), StatusCode::Ok);
        let cookie = get_csrf_cookie(&res).expect("Expected CSRF cookie in response.");
        assert_eq!(cookie.name(), "tide.csrf");

        let res = app.post("/").await?;
        assert_eq!(res.status(), StatusCode::Forbidden);

        // Send a valid (but mismatched) CSRF token and verify that we
        // get a Forbidden response.
        let res = app
            .post("/")
            .header(COOKIE, cookie.to_string())
            .header("X-CSRF-Token", csrf_token)
            .await?;
        assert_eq!(res.status(), StatusCode::Forbidden);

        Ok(())
    }

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
