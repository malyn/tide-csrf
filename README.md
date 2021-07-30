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

## Protected Methods

TODO Explain the concept of protected methods (and the middleware's
defaults) and that, by default, you must not mutate in `GET`! And if you
do, you have to add `GET` to your protected methods (which is a bit
expensive, so ideally do not do that).

## Examples

TODO

## Performance Considerations

TODO Explain the performance impact of putting the CSRF token in the
header vs. query params vs. forms.

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