// aria-gpu-miner — open-source GPU miner for EXFER, targeting AriaPool (and
// any Bitcoin-style stratum pool that speaks the same dialect).
//
// Pipeline per batch:
//   1. Snapshot the latest job + current pool difficulty.
//   2. For each of B nonces (starting from base_nonce + worker offset):
//        a. Write the nonce into header[84..92].
//        b. Compute pw  = SHA256( "EXFER-POW-P" || header ).
//        c. Compute salt = SHA256( "EXFER-POW-S" || header ).
//        d. unit.setPasswordAndSalt(i, pw, salt)
//   3. unit.beginProcessing() / endProcessing()   (Argon2id on GPU)
//   4. For each i: hash = unit.getHash(i); if hash < pool_target → submit share.
//      If hash < network_target → it's also a full block (pool will accept).

#include "stratum_client.hpp"
#include "exfer_prehash.hpp"

#include <argon2-cuda/globalcontext.h>
#include <argon2-cuda/programcontext.h>
#include <argon2-cuda/processingunit.h>
#include <argon2-gpu-common/argon2params.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <vector>

using namespace argon2;
using namespace argon2::cuda;

struct Args {
    std::string pool_url;       // stratum+tcp://host:port  (we strip the scheme)
    std::string wallet;
    std::string worker = "rig-1";
    std::size_t batch = 220;
    int device_index = 0;
    bool verbose = true;
};

static bool parse_pool_url(const std::string &url, std::string &host, std::uint16_t &port) {
    const std::string prefix = "stratum+tcp://";
    std::string s = url;
    if (s.rfind(prefix, 0) == 0) s = s.substr(prefix.size());
    auto colon = s.find(':');
    if (colon == std::string::npos) return false;
    host = s.substr(0, colon);
    int p = std::atoi(s.c_str() + colon + 1);
    if (p <= 0 || p > 65535) return false;
    port = (std::uint16_t)p;
    return true;
}

static void print_usage(const char *argv0) {
    std::cerr <<
        "Usage: " << argv0 << " --pool stratum+tcp://host:port"
        " --wallet <hex64> [--worker NAME] [--batch N] [--device N]\n";
}

static bool parse_args(int argc, char **argv, Args &a) {
    for (int i = 1; i < argc; ++i) {
        std::string k = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) return "";
            return argv[++i];
        };
        if (k == "--pool") a.pool_url = next();
        else if (k == "--wallet") a.wallet = next();
        else if (k == "--worker") a.worker = next();
        else if (k == "--batch") a.batch = (std::size_t)std::atoi(next().c_str());
        else if (k == "--device") a.device_index = std::atoi(next().c_str());
        else if (k == "-h" || k == "--help") return false;
        else { std::cerr << "Unknown arg: " << k << "\n"; return false; }
    }
    return !a.pool_url.empty() && !a.wallet.empty();
}

int main(int argc, char **argv) {
    Args args;
    if (!parse_args(argc, argv, args)) { print_usage(argv[0]); return 1; }

    std::string host;
    std::uint16_t port;
    if (!parse_pool_url(args.pool_url, host, port)) {
        std::cerr << "Bad --pool URL\n";
        return 1;
    }

    std::cerr << "aria-gpu-miner — EXFER GPU miner (Argon2id m=64MiB t=2 p=1)\n";
    std::cerr << "  pool   : " << host << ":" << port << "\n";
    std::cerr << "  wallet : " << args.wallet << "\n";
    std::cerr << "  worker : " << args.worker << "\n";
    std::cerr << "  batch  : " << args.batch << "\n\n";

    // GPU setup.
    GlobalContext gctx;
    const auto &devs = gctx.getAllDevices();
    if (devs.empty()) { std::cerr << "No CUDA device\n"; return 2; }
    if ((std::size_t)args.device_index >= devs.size()) {
        std::cerr << "device index out of range\n"; return 2;
    }
    std::vector<Device> devList{devs[args.device_index]};
    ProgramContext pctx(&gctx, devList, ::argon2::ARGON2_ID, ::argon2::ARGON2_VERSION_13);

    std::uint8_t placeholderSalt[32] = {0};
    Argon2Params argon2_params(
        32,
        placeholderSalt, 32,
        nullptr, 0,
        nullptr, 0,
        2, 65536, 1);

    std::cerr << "[gpu] init ProcessingUnit (batch=" << args.batch << ")...\n";
    ProcessingUnit unit(&pctx, &argon2_params, &devs[args.device_index],
                        args.batch, /*bySegment=*/true, /*precomputeRefs=*/false);
    std::cerr << "[gpu] ready\n";

    // Stratum.
    exfer::StratumClient client(host, port, args.wallet, args.worker);
    if (!client.connect_and_login()) { std::cerr << "stratum login failed\n"; return 3; }
    client.start();
    std::cerr << "[stratum] connected, waiting for first job...\n";

    // Wait up to 10 s for the first job.
    exfer::Job job;
    for (int s = 0; s < 100; ++s) {
        if (client.get_job(job)) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    if (job.header_template.empty()) {
        std::cerr << "no job received in 10 s\n";
        return 4;
    }
    std::cerr << "[stratum] first job " << job.job_id << "\n";

    // Random starting nonce window.
    std::mt19937_64 rng(std::random_device{}());
    std::uint64_t nonce_cursor = rng() & ~(std::uint64_t)0xffff; // 64K-aligned

    std::atomic<std::uint64_t> hashes_done{0};
    std::atomic<bool> stop{false};

    // Hashrate logger every 15 s.
    std::thread logger([&]{
        auto last = hashes_done.load();
        while (!stop.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(15));
            auto now = hashes_done.load();
            double hps = (now - last) / 15.0;
            std::cerr << "[rate] " << hps << " H/s · accepted=" << client.accepted_shares()
                      << " · rejected=" << client.rejected_shares() << "\n";
            last = now;
        }
    });

    // Mining loop.
    std::vector<std::uint8_t> header(exfer::HEADER_SIZE);
    std::uint8_t pw[32], salt[32], gpu_hash[32];
    std::uint8_t pool_target[32];

    while (true) {
        if (!client.is_alive()) {
            std::cerr << "[stratum] connection lost, exiting\n";
            break;
        }
        // Refresh job snapshot.
        exfer::Job cur;
        if (client.get_job(cur)) job = cur;
        std::uint64_t diff = client.get_difficulty();
        exfer::difficulty_to_target(diff, pool_target);

        std::uint64_t batch_base = nonce_cursor;
        nonce_cursor += args.batch;

        // Per-index pre-hash + upload.
        for (std::size_t i = 0; i < args.batch; ++i) {
            std::memcpy(header.data(), job.header_template.data(), exfer::HEADER_SIZE);
            std::uint64_t nonce = batch_base + i;
            exfer::prehash_for_nonce(header.data(), nonce, pw, salt);
            unit.setPasswordAndSalt(i, pw, 32, salt, 32);
        }

        unit.beginProcessing();
        unit.endProcessing();

        // Inspect each hash, submit winners.
        for (std::size_t i = 0; i < args.batch; ++i) {
            unit.getHash(i, gpu_hash);
            if (exfer::hash_below_target(gpu_hash, pool_target)) {
                std::uint64_t nonce = batch_base + i;
                std::cerr << "[share] job=" << job.job_id << " nonce="
                          << std::hex << nonce << std::dec << "\n";
                client.submit_share(job.job_id, nonce);
                if (exfer::hash_below_target(gpu_hash, job.network_target)) {
                    std::cerr << "[!!!] full block candidate!\n";
                }
            }
        }
        hashes_done.fetch_add(args.batch);
    }

    stop.store(true);
    if (logger.joinable()) logger.join();
    client.stop();
    return 0;
}
