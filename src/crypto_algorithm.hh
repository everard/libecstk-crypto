// Copyright(c) 2021 Nezametdinov E. Ildus.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)
//
#ifndef H_FBC6BB7618954D979B55C01C63E114A8
#define H_FBC6BB7618954D979B55C01C63E114A8

#include "buffer.hh"
#include <numeric>

namespace ecstk::crypto {
namespace std = ::std;

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

// Increments the integer written in little-endian form to the given byte range
// in constant time.
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
