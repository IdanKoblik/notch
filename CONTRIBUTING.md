# Contributing to notch

Thanks for your interest in contributing to **notch**, a network
steganography tool. Issues, ideas, and pull requests are very welcome.

By participating in this project, you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Getting started

1. **Fork** the repository and clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/notch.git
   cd notch
   ```
2. **Set up Rust.** notch is built with Cargo, so you'll need a recent stable
   Rust toolchain. If you don't have one, install it via
   [rustup](https://rustup.rs/).
3. **Build the project:**
   ```bash
   cargo build
   ```
4. **Run the test suite** before making changes, to confirm a clean baseline:
   ```bash
   cargo test
   ```

## Making changes

1. Create a new branch off `main` for your work:
   ```bash
   git checkout -b feature/short-description
   ```
2. Keep changes focused one feature or fix per branch/PR makes review much
   easier.
3. Match the existing code style. This repo uses an `.editorconfig`; make
   sure your editor respects it, and run:
   ```bash
   cargo fmt
   cargo clippy
   ```
   before committing, to catch formatting and lint issues.
4. Add or update tests for any behavior you change or introduce.
5. Update `CHANGELOG.md` with a short entry describing your change, if the
   project's convention calls for it.

## Commit messages

Write clear, descriptive commit messages that explain *why* a change was
made, not just what changed. Reference related issues where relevant, e.g.
`Fixes #12`.

## Submitting a pull request

1. Push your branch to your fork and open a pull request against `main`.
2. Describe what the PR does and why, and link any related issues.
3. Make sure CI checks (build, tests, lints) pass.
4. Be responsive to review feedback maintainers may ask for changes before
   merging.

## Reporting bugs

When filing a bug report, please include:

* Your OS and Rust version (`rustc --version`)
* Steps to reproduce the issue
* What you expected to happen vs. what actually happened
* Any relevant logs, error output, or sample files (with sensitive data
  redacted)

## Suggesting features

Feature requests are welcome via GitHub Issues. Please describe the use case
and, if possible, a rough idea of how it might work this helps maintainers
evaluate scope and fit for a steganography-focused tool.

## License

By contributing to notch, you agree that your contributions will be licensed
under the project's [GPL-3.0 License](LICENSE).
