// Copyright(c) 2021 Nezametdinov E. Ildus.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)
//
#include "../src/buffer.hh"

#include <iostream>
#include <iomanip>
#include <ranges>

template <ecstk::static_byte_buffer Buffer>
void
print(Buffer const& b) {
    static constexpr int line_width = 80;
    static constexpr int n_numbers_per_line = line_width / 2;

    for(std::size_t i{}, j{}; auto x : b) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)x;

        if(++j; (++i == n_numbers_per_line) && (j != b.size())) {
            i = 0;
            std::cout << '\n';
        }
    }

    std::cout << std::dec << '\n';
}

template <typename Range0, typename Range1>
auto
equal(Range0 const& x, Range1 const& y) {
    if(std::size(x) != std::size(y)) {
        return false;
    }

    return std::ranges::equal(x, y);
}

void
validate(bool v) {
    std::cout << "[valid result: " << int{v} << "]\n";

    if(!v) {
        std::exit(EXIT_FAILURE);
    }
}
