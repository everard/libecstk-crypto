// Copyright(c) 2021 Nezametdinov E. Ildus.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)
//
#ifndef H_638CA528DB7B4733A68B78D2C800DDF5
#define H_638CA528DB7B4733A68B78D2C800DDF5

#include "buffer.hh"
#include <optional>

namespace ecstk::crypto::pk_auth {
namespace std = ::std;

////////////////////////////////////////////////////////////////////////////////
// Public key authentication schema concept.
////////////////////////////////////////////////////////////////////////////////

// clang-format off
template <typename T>
concept schema =
    static_byte_buffer<T::public_key> &&
    static_byte_buffer<T::secret_key> &&
    static_byte_buffer<T::signature> &&
    std::copyable<T::keychain> &&
    requires(ref<T::secret_key> sk) {
        { T::keychain::initialize(sk) } ->
            std::same_as<std::optional<T::keychain>>;
    } &&
    requires(T::keychain const& kc) {
        { kc.pk() } -> std::convertible_to<T::public_key>;
    } &&
    requires(T::keychain const& kc, byte_sequence msg) {
        { T::sign(kc, msg) } -> std::same_as<T::signature>;
    } &&
    requires(ref<T::public_key> pk, ref<T::signature> sig, byte_sequence msg) {
        { T::verify(pk, sig, msg) } -> std::same_as<bool>;
    };
// clang-format on

} // namespace ecstk::crypto::pk_auth

#endif // H_638CA528DB7B4733A68B78D2C800DDF5
