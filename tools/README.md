# Development tools

Scratch programs used to cross-check the Rust legacy dialect against
ZeroTier's own C++ implementation. They are not part of the shipped
binaries.

| Tool | Purpose |
|---|---|
| `mh-check.cpp` | Compute ZeroTier's memory-hard identity hash for a public key set. Used to verify `zt_legacy::hashcash`. |
| `s20-check.cpp` | Compare ZeroTier's Salsa20 output against a reference implementation, to determine which state layout it uses. |

Build `mh-check.cpp` against a ZeroTier checkout:

```bash
ZT=~/compose/zerotierone
g++ -std=c++17 -O2 -o /tmp/mh-check tools/mh-check.cpp \
  -I"$ZT" -I"$ZT/include" -I"$ZT/ext" \
  "$ZT/node/ECC.cpp" "$ZT/node/Identity.cpp" "$ZT/node/SHA512.cpp" \
  "$ZT/node/Salsa20.cpp" "$ZT/node/Utils.cpp"

echo <public-key-hex> | /tmp/mh-check
```

The same job can be done from Rust:

```bash
echo <public-key-hex> | cargo run -p zt-legacy --example mh
```
