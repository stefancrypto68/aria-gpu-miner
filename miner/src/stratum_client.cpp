#include "stratum_client.hpp"
#include "exfer_prehash.hpp"  // HEADER_SIZE
#include "third_party/json.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>

using json = nlohmann::json;

namespace exfer {

static std::string nonce_to_hex(std::uint64_t nonce) {
    // EXFER nonce slot is 8 bytes little-endian. We mirror the on-wire convention
    // used by aria-miner (CPU) — the pool parses any hex of length 16 → u64 LE.
    char buf[17];
    for (int i = 0; i < 8; ++i) {
        std::snprintf(buf + 2 * i, 3, "%02x", (unsigned)((nonce >> (8 * i)) & 0xff));
    }
    buf[16] = 0;
    return std::string(buf);
}

static bool hex_to_bytes(const std::string &h, std::vector<std::uint8_t> &out) {
    if (h.size() % 2) return false;
    out.clear();
    out.reserve(h.size() / 2);
    for (std::size_t i = 0; i < h.size(); i += 2) {
        unsigned v;
        if (std::sscanf(h.c_str() + i, "%2x", &v) != 1) return false;
        out.push_back((std::uint8_t)v);
    }
    return true;
}

StratumClient::StratumClient(std::string host, std::uint16_t port,
                             std::string wallet, std::string worker)
    : host_(std::move(host)), port_(port),
      wallet_(std::move(wallet)), worker_(std::move(worker)) {}

StratumClient::~StratumClient() { stop(); }

bool StratumClient::connect_and_login() {
    // Resolve host.
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    std::string port_str = std::to_string(port_);
    int rc = getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0 || !res) {
        std::cerr << "getaddrinfo " << host_ << ": " << gai_strerror(rc) << "\n";
        return false;
    }
    sock_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock_ < 0) { freeaddrinfo(res); return false; }
    if (::connect(sock_, res->ai_addr, res->ai_addrlen) != 0) {
        std::perror("connect");
        ::close(sock_);
        sock_ = -1;
        freeaddrinfo(res);
        return false;
    }
    freeaddrinfo(res);

    // mining.subscribe
    json sub = {{"id", 1}, {"method", "mining.subscribe"}, {"params", json::array()}};
    if (!send_line(sub.dump())) return false;

    // mining.authorize
    std::string login = wallet_;
    if (!worker_.empty()) { login.push_back('.'); login += worker_; }
    json auth = {{"id", next_id_++}, {"method", "mining.authorize"},
                 {"params", {login, "x"}}};
    if (!send_line(auth.dump())) return false;

    alive_.store(true);
    return true;
}

void StratumClient::start() {
    reader_ = std::thread([this]{ reader_loop(); });
}

void StratumClient::stop() {
    stop_.store(true);
    alive_.store(false);
    if (sock_ >= 0) { ::shutdown(sock_, SHUT_RDWR); }
    if (reader_.joinable()) reader_.join();
    if (sock_ >= 0) { ::close(sock_); sock_ = -1; }
}

bool StratumClient::send_line(const std::string &line) {
    std::lock_guard<std::mutex> lk(write_mu_);
    std::string out = line + "\n";
    std::size_t off = 0;
    while (off < out.size()) {
        ssize_t n = ::send(sock_, out.data() + off, out.size() - off, MSG_NOSIGNAL);
        if (n <= 0) {
            alive_.store(false);
            return false;
        }
        off += (std::size_t)n;
    }
    return true;
}

int StratumClient::submit_share(const std::string &job_id, std::uint64_t nonce) {
    int id = next_id_++;
    json msg = {{"id", id}, {"method", "mining.submit"},
                {"params", {worker_, job_id, "00000000",
                            std::to_string((std::uint32_t)time(nullptr)),
                            nonce_to_hex(nonce)}}};
    send_line(msg.dump());
    return id;
}

void StratumClient::reader_loop() {
    char buf[4096];
    while (!stop_.load()) {
        ssize_t n = ::recv(sock_, buf, sizeof(buf), 0);
        if (n <= 0) { alive_.store(false); break; }
        read_buf_.append(buf, (std::size_t)n);
        std::size_t pos;
        while ((pos = read_buf_.find('\n')) != std::string::npos) {
            std::string line = read_buf_.substr(0, pos);
            read_buf_.erase(0, pos + 1);
            if (!line.empty()) handle_line(line);
        }
    }
}

void StratumClient::handle_line(const std::string &line) {
    json msg;
    try { msg = json::parse(line); } catch (...) {
        std::cerr << "[stratum] bad json: " << line << "\n";
        return;
    }

    try {

    auto method_it = msg.find("method");
    if (method_it != msg.end() && method_it->is_string()) {
        std::string method = method_it->get<std::string>();
        auto p = msg.value("params", json::array());

        if (method == "mining.set_difficulty" && p.is_array() && !p.empty()) {
            std::uint64_t diff = p[0].get<std::uint64_t>();
            difficulty_.store(diff);
            std::cerr << "[stratum] set_difficulty " << diff << "\n";
        } else if (method == "mining.notify" && p.is_array() && p.size() >= 5) {
            Job j;
            j.job_id = p[0].get<std::string>();
            std::vector<std::uint8_t> hdr;
            if (!hex_to_bytes(p[1].get<std::string>(), hdr) || hdr.size() != HEADER_SIZE) {
                std::cerr << "[stratum] notify: bad header\n";
                return;
            }
            j.header_template = std::move(hdr);
            std::vector<std::uint8_t> tgt;
            if (!hex_to_bytes(p[2].get<std::string>(), tgt) || tgt.size() != 32) {
                std::cerr << "[stratum] notify: bad target\n";
                return;
            }
            std::memcpy(j.network_target, tgt.data(), 32);
            j.timestamp = p[3].is_number() ? p[3].get<std::uint64_t>() : 0;
            j.clean_jobs = p[4].is_boolean() ? p[4].get<bool>() : false;

            bool clean = j.clean_jobs;
            std::string jid = j.job_id;
            {
                std::lock_guard<std::mutex> lk(job_mu_);
                latest_job_ = std::move(j);
            }
            std::cerr << "[stratum] new job " << jid << (clean ? " (clean)" : "") << "\n";
        }
        return;
    }

    // Reply (has "id" + "result"|"error")
    if (msg.contains("id")) {
        bool result_ok = msg.contains("result") && !msg["result"].is_null()
                         && (!msg["result"].is_boolean() || msg["result"].get<bool>());
        bool has_err = msg.contains("error") && !msg["error"].is_null();
        if (result_ok && !has_err) {
            // subscribe/authorize/submit ack
            accepted_.fetch_add(1);
        } else if (has_err) {
            rejected_.fetch_add(1);
            std::cerr << "[stratum] error: " << msg["error"].dump() << "\n";
        }
    }

    } catch (const std::exception &e) {
        std::cerr << "[stratum] handle_line exception: " << e.what()
                  << " line=" << line.substr(0, 200) << "\n";
    }
}

bool StratumClient::get_job(Job &out) const {
    std::lock_guard<std::mutex> lk(job_mu_);
    if (!latest_job_) return false;
    out = *latest_job_;
    return true;
}

void difficulty_to_target(std::uint64_t difficulty, std::uint8_t target[32]) {
    // MAX_TARGET / difficulty, where MAX_TARGET = 2^256 - 1.
    if (difficulty <= 1) { std::memset(target, 0xff, 32); return; }
    // Long division on 8 BE u32 limbs.
    std::uint32_t limbs[8];
    for (int i = 0; i < 8; ++i) limbs[i] = 0xffffffffu;
    std::uint32_t q[8] = {0};
    std::uint64_t rem = 0;
    for (int i = 0; i < 8; ++i) {
        rem = (rem << 32) | (std::uint64_t)limbs[i];
        q[i] = (std::uint32_t)(rem / difficulty);
        rem %= difficulty;
    }
    for (int i = 0; i < 8; ++i) {
        target[i*4 + 0] = (q[i] >> 24) & 0xff;
        target[i*4 + 1] = (q[i] >> 16) & 0xff;
        target[i*4 + 2] = (q[i] >> 8)  & 0xff;
        target[i*4 + 3] = (q[i] >> 0)  & 0xff;
    }
}

} // namespace exfer
