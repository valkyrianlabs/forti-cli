#include "sha256.hpp"

#include <forti/engine/error.hpp>

#include <algorithm>
#include <bit>
#include <cstring>

#include <stdlib.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/random.h>
#endif

namespace forti::engine::detail {

    namespace {

        constexpr std::array<std::uint32_t, 64> k = {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        };

        std::span<const std::uint8_t> bytes(std::string_view text) {
            return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
        }

    }  // namespace

    Sha256::Sha256()
            : state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19} {}

    void Sha256::compress(const std::uint8_t* block) {
        std::array<std::uint32_t, 64> w{};
        for (std::size_t i = 0; i < 16; ++i)
            w[i] = (std::uint32_t(block[4 * i]) << 24) | (std::uint32_t(block[4 * i + 1]) << 16) |
                   (std::uint32_t(block[4 * i + 2]) << 8) | std::uint32_t(block[4 * i + 3]);
        for (std::size_t i = 16; i < 64; ++i) {
            std::uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            std::uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        auto [a, b, c, d, e, f, g, h] = state_;
        for (std::size_t i = 0; i < 64; ++i) {
            std::uint32_t s1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
            std::uint32_t choose = (e & f) ^ (~e & g);
            std::uint32_t t1 = h + s1 + choose + k[i] + w[i];
            std::uint32_t s0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
            std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            std::uint32_t t2 = s0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

    Sha256& Sha256::update(std::span<const std::uint8_t> data) {
        length_ += data.size();
        std::size_t at = 0;
        if (used_ > 0) {
            std::size_t take = std::min(data.size(), 64 - used_);
            std::memcpy(block_.data() + used_, data.data(), take);
            used_ += take;
            at = take;
            if (used_ < 64) return *this;
            compress(block_.data());
            used_ = 0;
        }
        for (; at + 64 <= data.size(); at += 64) compress(data.data() + at);
        if (at < data.size()) {
            std::memcpy(block_.data(), data.data() + at, data.size() - at);
            used_ = data.size() - at;
        }
        return *this;
    }

    Sha256& Sha256::update(std::string_view data) { return update(bytes(data)); }

    Digest Sha256::finish() {
        std::uint64_t bits = length_ * 8;
        std::array<std::uint8_t, 72> pad{};
        pad[0] = 0x80;
        std::size_t pad_length = (used_ < 56 ? 56 - used_ : 120 - used_);
        for (std::size_t i = 0; i < 8; ++i) pad[pad_length + i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
        update(std::span<const std::uint8_t>(pad.data(), pad_length + 8));
        Digest out{};
        for (std::size_t i = 0; i < 8; ++i)
            for (std::size_t j = 0; j < 4; ++j) out[4 * i + j] = static_cast<std::uint8_t>(state_[i] >> (24 - 8 * j));
        return out;
    }

    Digest sha256(std::string_view data) { return Sha256().update(data).finish(); }

    std::string hex(std::span<const std::uint8_t> data) {
        static constexpr char digits[] = "0123456789abcdef";
        std::string out;
        out.reserve(data.size() * 2);
        for (std::uint8_t byte: data) {
            out += digits[byte >> 4];
            out += digits[byte & 15];
        }
        return out;
    }

    std::vector<std::uint8_t> random_bytes(std::size_t count) {
        std::vector<std::uint8_t> out(count);
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
        ::arc4random_buf(out.data(), out.size());
#else
        for (std::size_t at = 0; at < out.size(); at += 256)
            if (::getentropy(out.data() + at, std::min<std::size_t>(256, out.size() - at)) != 0)
                throw Failure(Code::internal, "the system random number generator is unavailable");
#endif
        return out;
    }

}  // namespace forti::engine::detail
