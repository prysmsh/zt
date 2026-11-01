#!/usr/bin/env bash
#
# Build the ZeroTier legacy oracle.
#
# The oracle links against ZeroTier's MPL-2.0 `node/` sources and emits
# golden test vectors in the shared JSON format. Track B uses it to verify
# that our Rust legacy shim is byte-identical to ZeroTier's implementation.
#
# Usage:
#   scripts/build-oracle.sh [path-to-zerotierone]
#
# Defaults to ~/compose/zerotierone.

set -euo pipefail

ZT_ROOT="${1:-$HOME/compose/zerotierone}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$PROJECT_ROOT/target/oracle"

if [[ ! -d "$ZT_ROOT/node" ]]; then
	echo "error: ZeroTier sources not found at $ZT_ROOT" >&2
	echo "usage: $0 [path-to-zerotierone]" >&2
	exit 1
fi

mkdir -p "$OUT_DIR"

echo "Building oracle against $ZT_ROOT"

# The oracle needs ZeroTier's node/ headers and sources. We compile only the
# translation units required for ECC, Identity, SHA-512 and credentials,
# avoiding the larger service/osdep surface.
g++ -std=c++17 -O2 -o "$OUT_DIR/zt-oracle" \
	-I"$ZT_ROOT" \
	-I"$ZT_ROOT/include" \
	-I"$ZT_ROOT/ext" \
	-I"$ZT_ROOT/ext/prometheus-cpp-lite-1.0/core/include" \
	-I"$ZT_ROOT/ext/prometheus-cpp-lite-1.0/simpleapi/include" \
	"$PROJECT_ROOT/oracle/zt_oracle.cpp" \
	"$ZT_ROOT/node/ECC.cpp" \
	"$ZT_ROOT/node/Identity.cpp" \
	"$ZT_ROOT/node/SHA512.cpp" \
	"$ZT_ROOT/node/Salsa20.cpp" \
	"$ZT_ROOT/node/Poly1305.cpp" \
	"$ZT_ROOT/node/CertificateOfMembership.cpp" \
	"$ZT_ROOT/node/InetAddress.cpp" \
	"$ZT_ROOT/node/Utils.cpp" \
	-lcrypto

echo "Built $OUT_DIR/zt-oracle"
