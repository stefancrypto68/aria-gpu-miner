# aria-gpu-miner

Open-source CUDA GPU miner for **EXFER** (Argon2id m=64 MiB, t=2, p=1).
**~1450 H/s on an RTX 5080** — within 3 % of the closed-source reference miner,
with 0 % dev-fee and a 1 % pool fee at [AriaPool](https://pool.ariabrain.com).

> **Status:** working. First open-source GPU miner for EXFER. Tested on
> Blackwell (RTX 5080) and Ada (RTX 40-series). AMD support via OpenCL build of
> the underlying argon2-gpu library — not packaged yet.

## How it works

EXFER PoW per nonce:

```
pw   = SHA-256( len("EXFER-POW-P") || "EXFER-POW-P" || header )
salt = SHA-256( len("EXFER-POW-S") || "EXFER-POW-S" || header )
hash = Argon2id(password=pw, salt=salt, m=64 MiB, t=2, p=1, out=32)
```

Each nonce produces a different header → a different `(pw, salt)` pair. To
batch many nonces on the GPU, we needed Argon2 with **per-index salt**. The
upstream `argon2-gpu` library only supports a single salt per batch (it's a
password-cracker, not a miner), so we ship a minimal patch:

- `Argon2Params::fillFirstBlocksWithSalt(memory, pwd, pwdLen, altSalt, altSaltLen, type, version)` — same initial-hash logic with a salt provided at runtime
- `ProcessingUnit::setPasswordAndSalt(index, pw, pwSize, salt, saltSize)` — feed one (pwd, salt) per batch slot

About **80 lines of CPU code, zero modification of the CUDA kernel**. Verified
against the reference `argon2id_hash_raw` (all 8 hashes match in
`miner/src/test_setpwsalt.cpp`).

The miner then:

1. Snapshots the latest job + pool difficulty from the stratum client.
2. For `--batch` nonces: writes nonce into header[84..92], computes pw/salt,
   calls `setPasswordAndSalt(i, …)`.
3. `beginProcessing` / `endProcessing` runs Argon2id on the GPU.
4. For each result: if hash < pool target → submit share; if hash < network
   target → also a full block.

## Build

Requires:
- CUDA 12+
- gcc-12 (CUDA 12.0 doesn't support gcc-13+)
- CMake 3.18+
- OpenSSL

```bash
git clone --recurse-submodules https://github.com/stefancrypto68/aria-gpu-miner
cd aria-gpu-miner

# 1) Build the patched argon2-gpu library
cd argon2-gpu && git submodule update --init
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc) argon2-cuda
cd ../..

# 2) Build the miner
g++-12 -std=c++17 -O2 -DHAVE_CUDA=1 -pthread \
  -I argon2-gpu/include -I argon2-gpu/ext/argon2/include \
  -I miner/src -I miner/src/third_party \
  miner/src/main.cpp miner/src/stratum_client.cpp \
  -L argon2-gpu/build -L argon2-gpu/build/ext/argon2 \
  -largon2-cuda -largon2-gpu-common -largon2 -lcudart -lcrypto -lssl \
  -L /usr/local/cuda/lib64 \
  -Wl,-rpath,$PWD/argon2-gpu/build \
  -Wl,-rpath,$PWD/argon2-gpu/build/ext/argon2 \
  -o miner/aria-gpu-miner
```

## Run

```bash
LD_LIBRARY_PATH=argon2-gpu/build:argon2-gpu/build/ext/argon2 \
  ./miner/aria-gpu-miner \
    --pool stratum+tcp://pool.ariabrain.com:3333 \
    --wallet <YOUR_EXFER_PUBKEY_HEX> \
    --worker rig-gpu \
    --batch 220
```

- `--batch 64` → ~4 GB VRAM, ~450 H/s
- `--batch 128` → ~8 GB VRAM, ~880 H/s
- `--batch 220` → ~14 GB VRAM, **~1450 H/s** (RTX 5080 / 4090)

Make sure your `--worker` name **contains `gpu`** (case-insensitive) so the
AriaPool dashboard places you in the GPU tier.

## What's not there yet

- Multi-GPU support inside a single process (run one process per GPU for now)
- AMD packaging (the underlying `argon2-gpu` supports OpenCL — patch is portable, just no CI yet)
- Auto-reconnect on stratum disconnect (you'll need a wrapper or systemd Restart=always)
- Auto-tuning batch size based on free VRAM

PRs welcome on all of the above.

## OC notes

Argon2id m=64 MiB on RTX 5080 is **memory-bandwidth-bound**, not power-bound.
Tested: memory offsets 0 → +2500 and power limit 250 W → 450 W all give the
same 1452 H/s — the GDDR7 boost is already at its BIOS-locked max (14801 MHz)
and the kernel only draws 206 W. Don't waste time OCing this card for EXFER.

## Licence

- Our patches and code (`miner/`, modifications to `argon2-gpu/lib` and
  `argon2-gpu/include`): MIT — see `LICENSE`.
- Upstream `argon2-gpu` by Ondrej Mosnáček: MIT — see `argon2-gpu/LICENSE`.
- Upstream `argon2` reference library: Apache-2.0 / CC0 — see
  `argon2-gpu/ext/argon2/LICENSE`.
- `nlohmann/json`: MIT, single-header.

## Related

- [aria-pool](https://github.com/stefancrypto68/aria-pool) — the pool itself
- [AriaPool dashboard](https://pool.ariabrain.com) — live stats
- [EXFER chain](https://github.com/ahuman-exfer/exfer) — upstream protocol
