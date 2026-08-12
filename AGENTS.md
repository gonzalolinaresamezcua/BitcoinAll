# AGENTS.md

## Cursor Cloud specific instructions

### What this repository is
"BitcoinAll Core" is a fork of Bitcoin Core (~v29.99): a single C++20 project built
with CMake that produces node/wallet/CLI binaries (`bitcoind`, `bitcoin-cli`,
`bitcoin-tx`, `bitcoin-util`, `bitcoin-wallet`, optional `bitcoin-qt`). There are
no long-running background services and no external database servers to start:
storage is embedded (LevelDB for chainstate/blocks, SQLite for the wallet).
Standard build/run/test commands live in `doc/build-unix.md`, `README.md`, and
`src/test/README.md` — refer to those rather than duplicating them.

### Build environment gotchas (durable, non-obvious)
- **Use GCC, not the default `c++`/`cc`.** On this image the `c++`/`cc`
  alternatives point to `clang`, which cannot find `libstdc++` (`cannot find
  -lstdc++`). Configure CMake with GCC explicitly:
  ```bash
  cmake -B build -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++
  cmake --build build -j"$(nproc)"
  ```
  `ccache` is installed and picked up automatically, so recompiles are fast.
- Optional features can be toggled at configure time, e.g. `-DWITH_ZMQ=ON`.
  The wallet (SQLite) is ON by default; the Qt GUI is OFF unless `-DBUILD_GUI=ON`.

### IMPORTANT: the application does not currently build from source
The development environment (compilers, CMake, Boost/libevent/SQLite/ZMQ,
Python) is fully set up and verified, but **the repository's own source code does
not compile** as of this writing. These are code defects, not environment/
dependency problems, and fixing them is application development (out of scope for
environment setup). Known blockers, roughly in build order:
- Incomplete file rename: `src/util/bitcoin_time.{h,cpp}` exist, but ~86 files
  still `#include <util/time.h>`.
- `src/util/CMakeLists.txt` adds `target_include_directories(bitcoin_util PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR})`, which puts `src/util/` on the include path and
  makes the standard `<cstring>`/`<ctime>` resolve `#include <string.h>`/
  `<time.h>` to the local `src/util/string.h`/`time.h` (compile errors like
  `'memchr' has not been declared in '::'`).
- Orphaned / stale code: a stray `CRegTestParams` constructor at file scope in
  `src/chainparams.cpp`; `#include <util/system.h>`, `#include <wallet/init.h>`
  and `#include <keyaddress.h>` reference headers that do not exist.
- Mixed Bitcoin Core API versions in the fork's custom "designated block
  proposer / uptime rewards" consensus feature: uses removed APIs
  (`uint256S`, `CDataStream`/`SER_NETWORK`, `CScript::IsOpReturn()`) in
  `src/kernel/chainparams.cpp`, `src/consensus/tx_verify.cpp`, `src/init.cpp`,
  and a declaration/definition mismatch for `GetUptime`/`GetLastRewardedUptime`
  between `src/coins.h` and `src/coins.cpp`.

Until the source is fixed, `bitcoind`/`bitcoin-cli`/etc. cannot be produced, so
running the node, unit tests (`ctest` / `test_bitcoin`), and Python functional
tests (`build/test/functional/test_runner.py`, which spawn regtest `bitcoind`)
are all blocked on the build.

### Verifying the environment itself
The vendored `secp256k1` subtree is self-contained and builds/tests cleanly, and
is a good smoke test that the toolchain works end to end:
```bash
cmake -S src/secp256k1 -B /tmp/secp_build -DSECP256K1_BUILD_TESTS=ON -DCMAKE_C_COMPILER=gcc
cmake --build /tmp/secp_build -j"$(nproc)"
ctest --test-dir /tmp/secp_build --output-on-failure
```

### Lint
Lint is a Rust-based runner: `(cd test/lint/test_runner && cargo run)`. Individual
linters may require extra tools (e.g. Python linters); see `test/lint/README.md`.
