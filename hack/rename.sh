#!/usr/bin/env bash

set -ex

TOP=$(realpath $(dirname $(dirname ${BASH_SOURCE[0]})))

pushd ${TOP}

find ${TOP} -type f -name "*.go" -exec sed -i 's/go.opentelemetry.io\/ebpf-profiler/github.com\/toliu\/opentelemetry-ebpf-profiler/g' {} +