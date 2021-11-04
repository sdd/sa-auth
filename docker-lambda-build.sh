#!/bin/bash
set -eu

docker run --rm \
  -it \
  -v "$PWD":/home/rust/src \
  -v cargo-git:/home/rust/.cargo/git \
  -v cargo-registry:/home/rust/.cargo/registry \
  -v target:/home/rust/src/target \
  ghcr.io/caddijp/rust-musl-builder/rust-musl-builder:1.55.0 \
  cargo build --release

cp target/x86_64-unknown-linux-musl/release/bootstrap ./bootstrap
rm bootstrap.zip || true
zip -r9 -j bootstrap.zip bootstrap