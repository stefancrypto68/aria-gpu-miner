// EXFER pre-hashing: derives the (pwd, salt) pair fed into Argon2id from
// a 156-byte block header carrying a candidate nonce.
//
// Spec (mirrors exfer/src/consensus/pow.rs):
//   pw   = SHA-256( len("EXFER-POW-P") || "EXFER-POW-P" || header )
//   salt = SHA-256( len("EXFER-POW-S") || "EXFER-POW-S" || header )
//   pow  = Argon2id(password=pw, salt=salt, m=65536, t=2, p=1, output=32)
//
// The nonce is the 8 little-endian bytes at header[84..92]. We mutate that
// slot in-place per candidate; everything else in the header is constant
// for a given job.

#pragma once

#include <openssl/sha.h>
#include <cstdint>
#include <cstring>

namespace exfer {

constexpr std::size_t HEADER_SIZE = 156;
constexpr std::size_t NONCE_OFFSET = 84;
constexpr std::size_t NONCE_SIZE = 8;

constexpr const char *DOMAIN_P = "EXFER-POW-P";
constexpr const char *DOMAIN_S = "EXFER-POW-S";

// SHA-256( len(sep) as u8 || sep || data ), per exfer Hash256::domain_hash.
inline void domain_hash(const char *sep, std::size_t sepLen,
                        const std::uint8_t *data, std::size_t dataLen,
                        std::uint8_t out[32])
{
    SHA256_CTX c;
    SHA256_Init(&c);
    std::uint8_t lenByte = (std::uint8_t)sepLen;
    SHA256_Update(&c, &lenByte, 1);
    SHA256_Update(&c, sep, sepLen);
    SHA256_Update(&c, data, dataLen);
    SHA256_Final(out, &c);
}

// Write a u64 nonce into the header slot (little-endian, matching EXFER).
inline void write_nonce(std::uint8_t *header, std::uint64_t nonce) {
    for (int i = 0; i < 8; ++i) {
        header[NONCE_OFFSET + i] = (std::uint8_t)((nonce >> (8 * i)) & 0xff);
    }
}

// Derive (pwd, salt) for a candidate. `header` must be a writable 156-byte
// buffer; this function mutates the nonce slot.
inline void prehash_for_nonce(std::uint8_t *header, std::uint64_t nonce,
                              std::uint8_t pw[32], std::uint8_t salt[32])
{
    write_nonce(header, nonce);
    domain_hash(DOMAIN_P, std::strlen(DOMAIN_P), header, HEADER_SIZE, pw);
    domain_hash(DOMAIN_S, std::strlen(DOMAIN_S), header, HEADER_SIZE, salt);
}

// Big-endian 256-bit compare: returns true if hash < target.
// Both buffers are 32 bytes, most-significant byte first.
inline bool hash_below_target(const std::uint8_t hash[32], const std::uint8_t target[32]) {
    return std::memcmp(hash, target, 32) < 0;
}

} // namespace exfer
