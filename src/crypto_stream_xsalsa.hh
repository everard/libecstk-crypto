// Copyright(c) 2021 Nezametdinov E. Ildus.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)
//
#ifndef H_C923DE805B064DF8807E6B692327347B
#define H_C923DE805B064DF8807E6B692327347B

#include "crypto_stream_salsa.hh"

namespace ecstk::crypto::stream::xsalsa {
namespace std = ::std;

////////////////////////////////////////////////////////////////////////////////
// Utility types.
////////////////////////////////////////////////////////////////////////////////

using std::size_t;
using std::uint64_t;

// Tag types.
enum struct key_tag {};
enum struct nonce_tag {};

////////////////////////////////////////////////////////////////////////////////
// Key and nonce types.
////////////////////////////////////////////////////////////////////////////////

using key = secure_buf<32, unsigned char, key_tag>;
using nonce = secure_buf<24, unsigned char, nonce_tag>;

static_assert(key::static_size() == salsa::key::static_size());
static_assert(nonce::static_size() ==
              static_sum<salsa::nonce::static_size(),
                         salsa::nonce_with_counter::static_size()>);

////////////////////////////////////////////////////////////////////////////////
// Cipher definition.
////////////////////////////////////////////////////////////////////////////////

template <size_t N>
struct cipher {
    using key = xsalsa::key;
    using nonce = xsalsa::nonce;

    cipher(ref<key> k, ref<nonce> n, uint64_t c = 0) noexcept
        : c0_{k.view_as<salsa::key>(), salsa::nonce{}}
        , c1_{salsa::key{}, salsa::nonce{}} {
        set_nonce(n, c);
    }

    void
    set_key(ref<key> k) noexcept {
        c0_.set_key(k.view_as<salsa::key>());
        update_();
    }

    void
    set_nonce(ref<nonce> n, uint64_t c = 0) noexcept {
        auto [c0_nc, c1_n] =
            n.view_as<salsa::nonce_with_counter, salsa::nonce>();

        c0_.set_nonce_with_counter(c0_nc);
        c1_.set_nonce(c1_n, c);

        update_();
    }

    void
    set_counter(uint64_t c) noexcept {
        c1_.set_counter(c);
    }

    void
    generate(mut_byte_sequence buf) noexcept {
        c1_.generate(buf);
    }

    void
    xor_buf(mut_byte_sequence buf) noexcept {
        c1_.xor_buf(buf);
    }

    auto
    counter() const noexcept -> uint64_t {
        return c1_.counter();
    }

private:
    void
    update_() noexcept {
        auto z = c0_.state();
        salsa::shuffle<N>(z);

        auto& x = c1_.state();

        x[1] = z[0];
        x[2] = z[5];
        x[3] = z[10];
        x[4] = z[15];

        x[11] = z[6];
        x[12] = z[7];
        x[13] = z[8];
        x[14] = z[9];
    }

    salsa::cipher<N> c0_, c1_;
};

} // namespace ecstk::crypto::stream::xsalsa

#endif // H_C923DE805B064DF8807E6B692327347B
