# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

### Added

### Changed

### Removed



## [0.3.0] - 2026-01-15

This release is for helping implement HyperDHT server.

### Added

* Add `Cipher::queue_msg`. Needed for HyperDHT
* Add `SecStream::new_responder_with_prologue`. Needed because HyperDHT responder is created with prologue.

### Changed

* Don't add errors to encrypted_rx when they come in. We were getting some errors from udx that would happen for each `poll`, forever.

### Removed



## [0.2.0] - 2025-12-29

### Added

* Add `Cipher`, `CipherIo`, and `CipherEvent`

### Changed

### Removed

<!-- next-url -->
[Unreleased]: https://github.com/cowlicks/hypercore_handshake/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/cowlicks/hypercore_handshake/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/cowlicks/hypercore_handshake/compare/v0.1.0...v0.2.0
