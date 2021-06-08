// Copyright Nezametdinov E. Ildus 2021.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)
//
#ifndef H_77B54A29755C479BBD07EED5594DA47C
#define H_77B54A29755C479BBD07EED5594DA47C

#include "buffer.hh"
#include <bit>

namespace ecstk::crypto::stream::salsa {
namespace std = ::std;

////////////////////////////////////////////////////////////////////////////////
// Utility types.
////////////////////////////////////////////////////////////////////////////////

// Require 8-bit bytes.
static_assert(CHAR_BIT == 8);

using std::size_t;
using std::uint32_t;
using std::uint64_t;

// Tag types.
enum struct key_tag {};
enum struct nonce_tag {};
enum struct nonce_with_counter_tag {};
enum struct state_tag {};

////////////////////////////////////////////////////////////////////////////////
// Key and nonce types.
////////////////////////////////////////////////////////////////////////////////

using key = secure_buf<32, unsigned char, key_tag>;
using nonce = secure_buf<8, unsigned char, nonce_tag>;
using nonce_with_counter =
    secure_buf<16, unsigned char, nonce_with_counter_tag>;

////////////////////////////////////////////////////////////////////////////////
// State vector.
////////////////////////////////////////////////////////////////////////////////

using state_vector = secure_buf<16, uint32_t, state_tag>;

static constexpr size_t block_size =
    state_vector::static_size() * sizeof(uint32_t);

namespace detail {

static constexpr uint32_t str[] = {
    0x61707865, 0x3320646E, 0x79622D32, 0x6B206574};

template <static_byte_buffer Buffer, static_buffer Map>
void
fill(state_vector& x, Buffer buf, Map map) noexcept {
    auto chunks = view_buffer_by_chunks<sizeof(uint32_t)>(buf);
    static_assert(decltype(chunks)::static_size() == Map::static_size());

    for(size_t i = 0; i < chunks.size(); ++i) {
        buffer_to_int(chunks[i], x[map[i]]);
    }
}

} // namespace detail

////////////////////////////////////////////////////////////////////////////////
// Core permutation.
////////////////////////////////////////////////////////////////////////////////

template <size_t N>
void
shuffle(state_vector& x) noexcept {
    static_assert((N >= 8) && ((N % 2) == 0));
    for(size_t i = 0; i < N / 2; ++i) {
        x[0x4] ^= std::rotl(x[0x0] + x[0xC], 0x07);
        x[0x8] ^= std::rotl(x[0x4] + x[0x0], 0x09);
        x[0xC] ^= std::rotl(x[0x8] + x[0x4], 0x0D);
        x[0x0] ^= std::rotl(x[0xC] + x[0x8], 0x12);
        x[0x9] ^= std::rotl(x[0x5] + x[0x1], 0x07);
        x[0xD] ^= std::rotl(x[0x9] + x[0x5], 0x09);
        x[0x1] ^= std::rotl(x[0xD] + x[0x9], 0x0D);
        x[0x5] ^= std::rotl(x[0x1] + x[0xD], 0x12);
        x[0xE] ^= std::rotl(x[0xA] + x[0x6], 0x07);
        x[0x2] ^= std::rotl(x[0xE] + x[0xA], 0x09);
        x[0x6] ^= std::rotl(x[0x2] + x[0xE], 0x0D);
        x[0xA] ^= std::rotl(x[0x6] + x[0x2], 0x12);
        x[0x3] ^= std::rotl(x[0xF] + x[0xB], 0x07);
        x[0x7] ^= std::rotl(x[0x3] + x[0xF], 0x09);
        x[0xB] ^= std::rotl(x[0x7] + x[0x3], 0x0D);
        x[0xF] ^= std::rotl(x[0xB] + x[0x7], 0x12);
        x[0x1] ^= std::rotl(x[0x0] + x[0x3], 0x07);
        x[0x2] ^= std::rotl(x[0x1] + x[0x0], 0x09);
        x[0x3] ^= std::rotl(x[0x2] + x[0x1], 0x0D);
        x[0x0] ^= std::rotl(x[0x3] + x[0x2], 0x12);
        x[0x6] ^= std::rotl(x[0x5] + x[0x4], 0x07);
        x[0x7] ^= std::rotl(x[0x6] + x[0x5], 0x09);
        x[0x4] ^= std::rotl(x[0x7] + x[0x6], 0x0D);
        x[0x5] ^= std::rotl(x[0x4] + x[0x7], 0x12);
        x[0xB] ^= std::rotl(x[0xA] + x[0x9], 0x07);
        x[0x8] ^= std::rotl(x[0xB] + x[0xA], 0x09);
        x[0x9] ^= std::rotl(x[0x8] + x[0xB], 0x0D);
        x[0xA] ^= std::rotl(x[0x9] + x[0x8], 0x12);
        x[0xC] ^= std::rotl(x[0xF] + x[0xE], 0x07);
        x[0xD] ^= std::rotl(x[0xC] + x[0xF], 0x09);
        x[0xE] ^= std::rotl(x[0xD] + x[0xC], 0x0D);
        x[0xF] ^= std::rotl(x[0xE] + x[0xD], 0x12);
    }
}

////////////////////////////////////////////////////////////////////////////////
// Generation and application of pseudo-random sequence.
////////////////////////////////////////////////////////////////////////////////

enum struct mode { cipher, prg };

template <size_t N, mode Mode, typename Fn>
void
apply(state_vector& x, mut_byte_sequence buf, Fn fn) noexcept
    requires(std::regular_invocable<Fn, byte_sequence, mut_byte_sequence>) {
    using block_storage =
        secure_buf<(std::endian::native != std::endian::little) ? block_size
                                                                : 0>;

    auto gen = [](state_vector& x, state_vector& y, block_storage& b) noexcept {
        shuffle<N>(y = x);
        for(size_t i = 0; i < y.size(); ++i) {
            y[i] += x[i];
        }

        if constexpr(block_storage::static_size() != 0) {
            auto chunks = view_buffer_by_chunks<sizeof(uint32_t)>(b);
            for(size_t i = 0; i < chunks.size(); ++i) {
                int_to_buffer(y[i], chunks[i]);
            }
        }

        x[9] += uint32_t{++x[8] == 0};

        if constexpr(Mode == mode::prg) {
            if((x[8] | x[9]) == 0) [[unlikely]] {
                x[7] += uint32_t{++x[6] == 0};
            }
        }
    };

    state_vector y;
    block_storage b;

    auto const block =
        byte_sequence{((block_storage::static_size() != 0)
                           ? b.data()
                           : reinterpret_cast<unsigned char const*>(y.data())),
                      block_size};

    for(; buf.size() >= block_size; buf = buf.subspan(block_size)) {
        gen(x, y, b);
        fn(block, buf.first(block_size));
    }

    if(buf.size() != 0) {
        gen(x, y, b);
        fn(block, buf);
    }
}

////////////////////////////////////////////////////////////////////////////////
// Cipher definition.
////////////////////////////////////////////////////////////////////////////////

template <size_t N>
struct cipher {
    using key = salsa::key;
    using nonce = salsa::nonce;

    cipher(ref<key> k, ref<nonce> n, uint64_t c = 0) noexcept : x_{} {
        x_[0] = detail::str[0];
        x_[5] = detail::str[1];
        x_[10] = detail::str[2];
        x_[15] = detail::str[3];

        set_key(k);
        set_nonce(n, c);
    }

    void
    set_key(ref<key> k) noexcept {
        detail::fill(x_, k, buffer<8>{1, 2, 3, 4, 11, 12, 13, 14});
    }

    void
    set_nonce(ref<nonce> n, uint64_t c = 0) noexcept {
        detail::fill(x_, n, buffer<2>{6, 7});
        set_counter(c);
    }

    void
    set_counter(uint64_t c) noexcept {
        x_[8] = static_cast<uint32_t>(c);
        x_[9] = static_cast<uint32_t>(c >> 32);
    }

    void
    set_nonce_with_counter(ref<nonce_with_counter> nc) noexcept {
        detail::fill(x_, nc, buffer<4>{6, 7, 8, 9});
    }

    void
    generate(mut_byte_sequence buf) noexcept {
        if(!buf.empty()) {
            apply<N, mode::cipher>(
                x_, buf, [](byte_sequence src, mut_byte_sequence dst) noexcept {
                    std::copy_n(src.data(), dst.size(), dst.data());
                });
        }
    }

    void
    xor_buf(mut_byte_sequence buf) noexcept {
        if(!buf.empty()) {
            apply<N, mode::cipher>(
                x_, buf, [](byte_sequence src, mut_byte_sequence dst) noexcept {
                    for(auto i = src.data(); auto& x : dst) {
                        x ^= *(i++);
                    }
                });
        }
    }

    auto
    state() noexcept -> state_vector& {
        return x_;
    }

    auto
    state() const noexcept -> state_vector const& {
        return x_;
    }

    auto
    counter() const noexcept -> uint64_t {
        return ((static_cast<uint64_t>(x_[8])) |
                (static_cast<uint64_t>(x_[9]) << 32));
    }

private:
    state_vector x_;
};

////////////////////////////////////////////////////////////////////////////////
// PRG definition. Size of the pseudo-random sequence is at least 2^128 bytes.
////////////////////////////////////////////////////////////////////////////////

template <size_t N>
struct prg {
    using key = salsa::key;

    prg(ref<key> k) noexcept : x_{} {
        x_[0] = detail::str[0];
        x_[5] = detail::str[1];
        x_[10] = detail::str[2];
        x_[15] = detail::str[3];

        detail::fill(x_, k, buffer<8>{1, 2, 3, 4, 11, 12, 13, 14});
    }

    void
    generate(mut_byte_sequence buf) noexcept {
        if(!buf.empty()) {
            apply<N, mode::prg>(
                x_, buf, [](byte_sequence src, mut_byte_sequence dst) noexcept {
                    std::copy_n(src.data(), dst.size(), dst.data());
                });
        }
    }

private:
    state_vector x_;
};

} // namespace ecstk::crypto::stream::salsa

#endif // H_77B54A29755C479BBD07EED5594DA47C
