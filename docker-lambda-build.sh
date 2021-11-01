#!/bin/bash
set -eu

docker run --rm \
  -v "$PWD":/var/task \
  lambci/lambda:build-provided.al2 \
  /bin/bash ./customize-lambci.sh

cp target/x86_64-unknown-linux-musl/release/bootstrap ./bootstrap
rm bootstrap.zip
zip -r9 -j bootstrap.zip bootstrap