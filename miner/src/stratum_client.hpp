// Minimal Bitcoin-style stratum client for AriaPool (EXFER).
//
// Wire protocol (one JSON object per line, "\n"-terminated):
//   → mining.subscribe         []
//   ← [["mining.set_difficulty", id], ["mining.notify", id]], extranonce1, extranonce2_size
//   → mining.authorize         [login_string]           (login = "<wallet_hex>[.<rig>]")
//   ← true
//   ← mining.set_difficulty    [diff:u64]               (notification)
//   ← mining.notify            [job_id, header_hex, network_target_hex, timestamp, clean_jobs]
//   → mining.submit            [worker, job_id, extranonce2, ntime, nonce_hex]
//   ← true / err
//
// Run loop:
//   - one reader thread parses incoming lines and updates the shared Job/Difficulty.
//   - the caller posts shares via submit_share() from any thread.

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace exfer {

struct Job {
    std::string job_id;
    std::vector<std::uint8_t> header_template;   // 156 bytes
    std::uint8_t network_target[32]{};           // big-endian 256-bit
    std::uint64_t timestamp{0};
    bool clean_jobs{false};
};

class StratumClient {
public:
    StratumClient(std::string host, std::uint16_t port,
                  std::string wallet, std::string worker);
    ~StratumClient();

    /// Blocks until subscribe+authorize succeed (or returns false on error).
    bool connect_and_login();

    /// Spawn the reader thread. After this, get_job()/get_difficulty()
    /// observe the latest pool state.
    void start();

    void stop();

    /// Most recent job (copy). Returns false if no job has been received yet.
    bool get_job(Job &out) const;

    /// Current vardiff (default 1).
    std::uint64_t get_difficulty() const { return difficulty_.load(); }

    /// Submit a winning share. Returns the JSON-RPC id used (>0).
    /// Non-blocking: enqueues the line on the writer side.
    int submit_share(const std::string &job_id, std::uint64_t nonce);

    /// Whether the client is still considered alive (socket up, no fatal error).
    bool is_alive() const { return alive_.load(); }

    /// Stats counters.
    std::uint64_t accepted_shares() const { return accepted_.load(); }
    std::uint64_t rejected_shares() const { return rejected_.load(); }

private:
    void reader_loop();
    void handle_line(const std::string &line);
    bool send_line(const std::string &line);

    std::string host_;
    std::uint16_t port_;
    std::string wallet_;
    std::string worker_;

    int sock_{-1};
    std::atomic<bool> alive_{false};
    std::atomic<bool> stop_{false};
    std::atomic<int> next_id_{2}; // 1 = subscribe, 2 = authorize, rest = submits
    std::atomic<std::uint64_t> difficulty_{1};
    std::atomic<std::uint64_t> accepted_{0};
    std::atomic<std::uint64_t> rejected_{0};

    mutable std::mutex job_mu_;
    std::optional<Job> latest_job_;

    std::mutex write_mu_;
    std::string read_buf_;
    std::thread reader_;
};

/// 256-bit target derived from a stratum difficulty value (BE bytes).
/// MAX_TARGET = 0xff..ff; target = MAX_TARGET / difficulty.
void difficulty_to_target(std::uint64_t difficulty, std::uint8_t target[32]);

} // namespace exfer
