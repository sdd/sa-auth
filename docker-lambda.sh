#!/bin/bash
set -eu

docker run --rm \
  -e DOCKER_LAMBDA_STAY_OPEN=1 \
  -p 9001:9001 \
  -v "$PWD":/var/task:ro,delegated \
  lambci/lambda:provided.al2 \
  bootstrap