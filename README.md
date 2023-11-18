# CryptoURI.rs

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
[![Safety Dance][safety-image]][safety-link]
![Apache 2.0+MIT Licensed][license-image]
![MSRV][msrv-image]

A URI-like format for serializing cryptographic objects including keys,
signatures, and digests using URI generic syntax:

```
crypto:pub:key:ed25519:6adfsqvzky9t042tlmfujeq88g8wzuhnm2nzxfd0qgdx3ac82ydqf03cvv
```

A URI-safe "dasherized" form is also supported:

```
crypto-pub-key-ed25519-6adfsqvzky9t042tlmfujeq88g8wzuhnm2nzxfd0qgdx3ac82ydqlu986g
```

[Documentation][docs-link]

## About CryptoURI

The CryptoURI format leverages the URI generic syntax defined in [RFC 3986] to
provide simple and succinct encodings of cryptographic keys, including public
keys, private/secret keys, encrypted secret keys with password-based key
derivation, digital signatures, key fingerprints, and other digests.

Binary data is serialized using the [Bech32] encoding format which is designed
to prevent human transcription errors by using an alphabet that eliminates
similar-looking characters to avoid transcription errors and adds a checksum
across the whole URI to detect these errors when they do happen.
CryptoURIs which have been mis-transcribed will fail to decode.

## Minimum Supported Rust Version

- Rust **1.60+**

## Code of Conduct

We abide by the [Contributor Covenant][cc] and ask that you do as well.

For more information, please see [CODE_OF_CONDUCT.md].

## Contributing

Bug reports and pull requests are welcome on GitHub at:

<https://github.com/cryptouri/cryptouri.rs>

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as noted below, without any additional terms or
conditions.

## License

The **cryptouri** Rust crate is dual licensed under your choice of either of:

- Apache License, Version 2.0, ([LICENSE-APACHE] or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT] or http://opensource.org/licenses/MIT)

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/cryptouri
[crate-link]: https://crates.io/crates/cryptouri
[docs-image]: https://docs.rs/cryptouri/badge.svg
[docs-link]: https://docs.rs/cryptouri/
[build-image]: https://github.com/cryptouri/cryptouri.rs/actions/workflows/cryptouri.yml/badge.svg
[build-link]: https://github.com/cryptouri/cryptouri.rs/actions/workflows/cryptouri.yml
[safety-image]: https://img.shields.io/badge/unsafe-forbidden-success.svg
[safety-link]: https://github.com/rust-secure-code/safety-dance/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.60+-blue.svg

[//]: # (links)

[Bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
[cc]: https://contributor-covenant.org
[CODE_OF_CONDUCT.md]: https://github.com/cryptouri/cryptouri-rs/blob/develop/CODE_OF_CONDUCT.md
[RFC 3986]: https://tools.ietf.org/html/rfc3986
[LICENSE-APACHE]: https://github.com/cryptouri/cryptouri-rs/blob/develop/LICENSE-APACHE
[LICENSE-MIT]: https://github.com/cryptouri/cryptouri-rs/blob/develop/LICENSE-MIT
