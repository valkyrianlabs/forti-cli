//
// Engine-internal SHA-256 (FIPS 180-4) for plan digests and before-state digests. Small and
// self-contained so the engine adds no library dependency; checked against the NIST vectors in
// tests/unit/test_plan.cpp.
//

#ifndef FORTI_ENGINE_SHA256_HPP
#define FORTI_ENGINE_SHA256_HPP

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace forti::engine::detail {

    using Digest = std::array<std::uint8_t, 32>;

    class Sha256 {
        std::array<std::uint32_t, 8> state_;
        std::array<std::uint8_t, 64> block_{};
        std::size_t used_ = 0;
        std::uint64_t length_ = 0;   // bytes

        void compress(const std::uint8_t* block);

    public:
        Sha256();
        Sha256& update(std::span<const std::uint8_t> data);
        Sha256& update(std::string_view data);
        Digest finish();
    };

    Digest sha256(std::string_view data);
    std::string hex(std::span<const std::uint8_t> bytes);

    // Bytes from the OS CSPRNG (arc4random_buf on Apple/BSD, getentropy elsewhere): plan id suffixes.
    std::vector<std::uint8_t> random_bytes(std::size_t count);

}  // namespace forti::engine::detail

#endif  // FORTI_ENGINE_SHA256_HPP
