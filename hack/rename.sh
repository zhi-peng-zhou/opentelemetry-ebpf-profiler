#!/usr/bin/env bash

set -ex

TOP=$(realpath $(dirname $(dirname ${BASH_SOURCE[0]})))

pushd ${TOP}

find ${TOP} -type f -name "*.go" -exec sed -i 's/github.com\/open-telemetry\/opentelemetry-ebpf-profiler/github.com\/toliu\/opentelemetry-ebpf-profiler/g' {} +