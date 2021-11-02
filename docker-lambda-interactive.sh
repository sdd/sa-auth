#!/bin/bash
set -eu

docker run \
  -e DOCKER_LAMBDA_STAY_OPEN=1 \
  -e DOCKER_LAMBDA_DEBUG=1 \
  -e RUST_LOG=debug \
  -e RUST_BACKTRACE=1 \
  -p 9001:9001 \
  -it \
  --entrypoint /bin/bash \
  -v "$PWD":/var/task \
  -v ~/.cargo/git:/root/.cargo/git \
  -v ~/.cargo/registry:/root/.cargo/registry \
  lambci/lambda:build-provided.al2
  