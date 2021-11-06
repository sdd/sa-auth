#!/bin/bash
set -eu

docker run --rm \
  -e DOCKER_LAMBDA_STAY_OPEN=1 \
  -e DOCKER_LAMBDA_DEBUG=1 \
  -p 9001:9001 \
  -e RUST_LOG=debug \
  -e RUST_BACKTRACE=1 \
  -e JWT_SECRET=secret \
  -e GOOGLE_CLIENT_ID=cid \
  -e GOOGLE_CLIENT_SECRET=csec \
  -v "$PWD":/var/task:ro,delegated \
  lambci/lambda:provided.al2 \
  bootstrap