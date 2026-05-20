// Validates the EXFER setPasswordAndSalt patch against a CPU reference
// implementation. Builds N hashes with distinct (pwd, salt) pairs on the
// GPU in a single batch, then compares each output with argon2id_hash_raw.

#include <argon2-cuda/globalcontext.h>
#include <argon2-cuda/programcontext.h>
#include <argon2-cuda/processingunit.h>
#include <argon2-gpu-common/argon2params.h>

#include <argon2.h>

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>

using namespace argon2;
using namespace argon2::cuda;

static const std::size_t M_COST   = 65536; // 64 MiB
static const std::size_t T_COST   = 2;
static const std::size_t LANES    = 1;
static const std::size_t OUT_LEN  = 32;
static const std::size_t BATCH    = 8;
static const std::size_t PWLEN    = 32;
static const std::size_t SALTLEN  = 32;

static void print_hex(const std::uint8_t *p, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) std::printf("%02x", p[i]);
}

int main() {
    GlobalContext gctx;
    const auto &devices = gctx.getAllDevices();
    if (devices.empty()) {
        std::cerr << "No CUDA device\n";
        return 1;
    }
    std::vector<Device> devList{devices[0]};
    ProgramContext pctx(&gctx, devList, ::argon2::ARGON2_ID, ::argon2::ARGON2_VERSION_13);

    // The salt set in Params is a placeholder — setPasswordAndSalt overrides it.
    std::uint8_t placeholderSalt[SALTLEN] = {0};
    Argon2Params params(
        OUT_LEN,
        placeholderSalt, SALTLEN,
        nullptr, 0,
        nullptr, 0,
        T_COST, M_COST, LANES);

    ProcessingUnit unit(&pctx, &params, &devices[0], BATCH, true, false);

    // Distinct (pwd, salt) per index.
    std::vector<std::vector<std::uint8_t>> pws(BATCH), salts(BATCH);
    for (std::size_t i = 0; i < BATCH; ++i) {
        pws[i].resize(PWLEN);
        salts[i].resize(SALTLEN);
        for (std::size_t k = 0; k < PWLEN; ++k)   pws[i][k]   = (std::uint8_t)(i * 11 + k);
        for (std::size_t k = 0; k < SALTLEN; ++k) salts[i][k] = (std::uint8_t)(i * 17 + k + 0x80);
        unit.setPasswordAndSalt(i, pws[i].data(), PWLEN, salts[i].data(), SALTLEN);
    }

    auto t0 = std::chrono::steady_clock::now();
    unit.beginProcessing();
    unit.endProcessing();
    auto t1 = std::chrono::steady_clock::now();

    std::size_t mismatches = 0;
    for (std::size_t i = 0; i < BATCH; ++i) {
        std::uint8_t gpu_hash[OUT_LEN] = {0};
        std::uint8_t cpu_hash[OUT_LEN] = {0};

        unit.getHash(i, gpu_hash);

        int rc = argon2id_hash_raw(
            T_COST, M_COST, LANES,
            pws[i].data(), PWLEN,
            salts[i].data(), SALTLEN,
            cpu_hash, OUT_LEN);

        if (rc != ARGON2_OK) {
            std::cerr << "[" << i << "] argon2id_hash_raw error: " << rc << "\n";
            ++mismatches;
            continue;
        }

        bool match = std::memcmp(gpu_hash, cpu_hash, OUT_LEN) == 0;
        std::cout << "[" << i << "] ";
        if (match) {
            std::cout << "MATCH  gpu=";
            print_hex(gpu_hash, 8);
            std::cout << "...\n";
        } else {
            ++mismatches;
            std::cout << "MISMATCH\n";
            std::cout << "    gpu=";
            print_hex(gpu_hash, OUT_LEN);
            std::cout << "\n    cpu=";
            print_hex(cpu_hash, OUT_LEN);
            std::cout << "\n";
        }
    }

    auto ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    double hps = BATCH * 1000.0 / ms;
    std::cout << "\nBatch " << BATCH << " in " << ms << " ms → "
              << hps << " H/s (single-batch, no steady-state)\n";

    if (mismatches) {
        std::cout << "FAIL : " << mismatches << "/" << BATCH << " mismatches\n";
        return 2;
    }
    std::cout << "PASS : all " << BATCH << " hashes match CPU reference\n";
    return 0;
}
