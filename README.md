tide-csrf
=========

[![Build Status](https://github.com/malyn/tide-csrf/actions/workflows/main.yml/badge.svg)](https://github.com/malyn/tide-csrf/actions/workflows/main.yml)
[![Latest version](https://img.shields.io/crates/v/tide-csrf.svg)](https://crates.io/crates/tide-csrf)
[![Documentation](https://docs.rs/tide-csrf/badge.svg)](https://docs.rs/tide-csrf)
![License](https://img.shields.io/crates/l/tide-csrf.svg)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](https://github.com/malyn/tide-csrf/blob/main/CODE_OF_CONDUCT.md) 

Cross-Site Request Forgery (CSRF) protection middleware for Tide.

This crate provides middleware that helps you defend against CSRF
attacks. The middleware generates a CSRF cookie and adds it to your Tide
response, and then generates a CSRF token and makes it available to your
Tide request. In your HTML, you then arrange for the CSRF token to be
returned to the server on subsequent requests, either in a request
header, a query parameter, or a form field. The middleware then verifies
that a CSRF token is present and valid whenever a request is received
for a protected method.

- [Documentation](https://docs.rs/tide-csrf)
- [Release notes](https://github.com/malyn/tide-csrf/releases)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
tide-csrf = "0.1"
```

## Example

```rust
use tide_csrf::{self, CsrfRequestExt};

let mut app = tide::new();

app.with(tide_csrf::CsrfMiddleware::new(
    b"we recommend you use std::env::var(\"TIDE_SECRET\").unwrap().as_bytes() instead of a fixed value"
));

// This is an unprotected method and does not require a CSRF token
// (but will set the CSRF cookie).
app.at("/").get(|req: tide::Request<()>| async move {
    // Note that here we are simply returning the token in a string, but
    // in a real application you need to arrange for the token to appear
    // in the request to the server.
    Ok(format!(
        "CSRF token is {}; you should return that in header {}, or query param {}, or a form field named {}",
        req.csrf_token(),
        req.csrf_header_name(),
        req.csrf_query_param(),
        req.csrf_field_name()
    ))
});

// This is a protected method and will only allow the request to
// make it to the handler if the CSRF token is present in the
// request. Otherwise an HTTP status of `Forbidden` will be
// returned and the handler will *not* be called.
app.at("/").post(|req: tide::Request<()>| async move {
   Ok("Getting this far means that the CSRF token was present in the request.")
});
```

## Protected Methods

By default, this middleware protects only those HTTP methods that might
mutate state on the server. Those "unsafe" methods are `POST`, `PUT`,
`PATCH`, and `DELETE`. The remaining methods -- `GET`, `HEAD`, etc. --
are *not* protected by default. This limits the performance impact of
the middleware on your application.

However, if your application *does* mutate state in those "safe" methods
then you need to [set the list of protected
methods](CsrfMiddleware::with_protected_methods) to include those other
methods.

Note that protecting `GET` may create a "chicken and egg" situation
where you have no way to return the CSRF cookie and token to a caller
for them to return back to you in a subsequent request! In general, the
default list of methods is the correct one and you should ensure that
the "safe" methods are in fact truly safe and do not perform any
mutations.

## Performance Considerations

This middleware adds a CSRF cookie to every request and looks for a
matching CSRF token when processing a request for a protected method.
The CSRF token can be returned in an HTTP header, the URL query string,
or an `application/x-www-form-urlencoded` form body. The token is
searched for in that order and the search will be terminated as soon as
the token is found.

The most efficient place to search for the token is in an HTTP header
and that mechanism should be preferred if you have the ability to set
headers in the request. The query string is a good option if you cannot
set HTTP headers.

Using form fields is the least efficient way to return the CSRF token
because the middleware has to read and deserialize the entire request
body in order to see if the token is present, and then make a full,
in-memory copy of the body available to your application. Tide request
bodies are normally streamed to the application, so performing this
extra deserialization and memory copy step is quite expensive relative
to the normal request flow.

For this reason, the middleware searches the form fields last *and* only
considers `application/x-www-form-urlencoded` requests;
`multipart/form-data` bodies, which may contain large binary payloads,
are *not* searched. If you need to protect `multipart/form-data`
requests then you should return the CSRF token in an HTTP header or the
query string.

## Conduct

This project adheres to the [Contributor Covenant Code of
Conduct](https://github.com/malyn/tide-csrf/blob/main/CODE_OF_CONDUCT.md).
This describes the minimum behavior expected from all contributors.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](https://github.com/malyn/tide-csrf/blob/main/LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](https://github.com/malyn/tide-csrf/blob/main/LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms
or conditions.