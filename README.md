tide-csrf
=========

[![Build Status](https://github.com/malyn/tide-csrf/actions/workflows/main.yml/badge.svg)](https://github.com/malyn/tide-csrf/actions/workflows/main.yml)
[![Latest version](https://img.shields.io/crates/v/tide-csrf.svg)](https://crates.io/crates/tide-csrf)
[![Documentation](https://docs.rs/tide-csrf/badge.svg)](https://docs.rs/tide-csrf)
![License](https://img.shields.io/crates/l/tide-csrf.svg)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.0-4baaaa.svg)](CODE_OF_CONDUCT.md) 

Cross-Site Request Forgery (CSRF) protection middleware for Tide.

- [Documentation](https://docs.rs/tide-csrf)
- [Release notes](https://github.com/malyn/tide-csrf/releases)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
tide-csrf = "0.1"
```

## Examples

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

## Conduct

This project adheres to the [Contributor Covenant Code of
Conduct](https://github.com/malyn/tide-csrf/blob/main/CODE_OF_CONDUCT.md).
This describes the minimum behavior expected from all contributors.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms
or conditions.