* This crate includes `tracing` as a dependency. Important functions should use `#[tracing::instrument]`
* Change `REPOSITORY_NAME` in `CHANGELOG.md` and `release.toml`: `find . -type f -exec sed -i 's/REPOSITORY_NAME/yor_repo_name/g' {} +`

* `.gitignore` includes `Cargo.lock`. I prefer this, but there are often reasons to track the lock.
* some auto-allow lints are warned
    - TODO add more
    - TODO add clippy lints
* TODO add a script fill template words
* TODO add git hooks:
    - check unused deps
* TODO add ci template
* TODO add a template for integration testing for different languages, automatically setting stuff up with `make`

# Usage

## formatting

To format source code, `rustfmt` needs to run with nightly ([more info](https://github.com/rust-lang/rustfmt?tab=readme-ov-file#on-the-nightly-toolchain)): `cargo +nightly fmt`.

## Releasing

* Releasing run `cargo release  ... `
