// Copyright Nezametdinov E. Ildus 2021.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)
//
#ifndef H_FBC6BB7618954D979B55C01C63E114A8
#define H_FBC6BB7618954D979B55C01C63E114A8

#include "crypto_concepts.hh"

namespace ecstk::crypto {
namespace std = ::std;

////////////////////////////////////////////////////////////////////////////////
// Buffer generation.
////////////////////////////////////////////////////////////////////////////////

// Generates and returns a buffer of the given type.
template <typename Generator, static_byte_buffer Buffer>
auto
generate(Generator&& g) noexcept -> Buffer
    requires(prg::schema<std::remove_reference_t<Generator>> ||
             stream::cipher<std::remove_reference_t<Generator>>) {
    Buffer r;
    return (void)g.generate(mut_byte_sequence{r}), r;
}

////////////////////////////////////////////////////////////////////////////////
// Constant-time algorithms.
////////////////////////////////////////////////////////////////////////////////

// Checks the equality of the given byte ranges in constant time.
template <byte_range Range0, byte_range Range1>
auto
equals(Range0 const& x, Range1 const& y) noexcept -> bool {
    return ((std::ranges::size(x) == std::ranges::size(y)) &&
            (std::inner_product(
                 std::begin(x), std::end(x), std::begin(y), 0U,
                 [](auto a, auto c) { return a | c; },
                 [](auto x, auto y) { return x ^ y; }) == 0));
}

// Increments (in constant time) an integer which is written in little-endian
// form to the given byte range.
template <byte_range Integer>
void
increment(Integer& i) noexcept {
    using carry =
        std::conditional_t<(std::numeric_limits<unsigned>::digits > CHAR_BIT),
                           unsigned, unsigned long>;

    static_assert(std::numeric_limits<carry>::digits > CHAR_BIT);

    for(auto c = carry{1}; auto& x : i) {
        x = static_cast<unsigned char>(c += x);
        c >>= CHAR_BIT;
    }
}

} // namespace ecstk::crypto

#endif // H_FBC6BB7618954D979B55C01C63E114A8
