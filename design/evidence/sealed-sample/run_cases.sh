#!/usr/bin/env bash
# Run from this folder. Each case prints the command, its output and its exit code.
show() {
  echo "\$ verifier $*"
  ./verifier "$@" 2>&1
  echo "exit code: $?"
  echo
}
K="--root-key seal-pub.pem --master-key ikm.bin"
show verify --ledger ledger.ndjson $K
show verify --ledger cut-last.ndjson $K
show verify --ledger rewrite-old-seal.ndjson $K
show verify --ledger rewrite-new-root.ndjson $K
show verify --ledger rewrite-own-signature.ndjson $K
show verify --ledger rewrite-own-signature.ndjson --root-key own-key-pub.pem --master-key ikm.bin
