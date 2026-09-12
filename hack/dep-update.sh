#!/usr/bin/env bash

set -ex

export GO111MODULE=on
export _sync_only="false"

while true; do
    case "$1" in
    -s | --sync-only)
        _sync_only="true"
        shift 1
        ;;
    --)
        shift
        break
        ;;
    *) break ;;
    esac
done

(
    echo $_sync_only
    cd staging/src/kubevirt.io/api
    if [ "${_sync_only}" == "false" ]; then go get $@ ./...; fi
    go mod tidy
)
(
    echo $_sync_only
    cd staging/src/kubevirt.io/client-go
    if [ "${_sync_only}" == "false" ]; then go get $@ ./...; fi
    go mod tidy
)

(
    cd staging/src/kubevirt.io/client-go/examples/listvms
    if [ "${_sync_only}" == "false" ]; then go get $@ ./...; fi
    go mod tidy
)

go mod tidy
go work sync
go work vendor

# Go's vendor command omits the emulator's non-Go C source directory.
# Copy it from the checksum-verified, pinned module for offline TPM tests.
tpm_simulator_module=$(GOWORK=off go list -mod=mod -m -f '{{.Dir}}' github.com/google/go-tpm-tools)
cp -R "${tpm_simulator_module}/simulator/ms-tpm-20-ref" vendor/github.com/google/go-tpm-tools/simulator/
chmod -R u+w vendor/github.com/google/go-tpm-tools/simulator/ms-tpm-20-ref

cat >vendor/github.com/google/go-tpm-tools/simulator/ms-tpm-20-ref/BUILD.bazel <<'EOF'
# Upstream includes these C sources from simulator/internal/include.c.
cc_library(
    name = "headers",
    textual_hdrs = glob(["**/*.h", "**/*.c", "**/*.inc"]),
    visibility = ["//vendor/github.com/google/go-tpm-tools/simulator/internal:__pkg__"],
)
EOF
