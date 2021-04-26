// Copyright(c) 2021 Nezametdinov E. Ildus.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)
//
#ifndef H_7EF44563B1C6470B8FFFEFB77C5D88DF
#define H_7EF44563B1C6470B8FFFEFB77C5D88DF

#include "buffer.hh"
#include <optional>

namespace ecstk::crypto::kx {
namespace std = ::std;

////////////////////////////////////////////////////////////////////////////////
// Side of the key exchange.
////////////////////////////////////////////////////////////////////////////////

enum struct side { client, server };

////////////////////////////////////////////////////////////////////////////////
// Key exchange schema concept.
////////////////////////////////////////////////////////////////////////////////

// clang-format off
template <typename T>
concept schema =
    static_byte_buffer<T::public_key> &&
    static_byte_buffer<T::secret_key> &&
    static_byte_buffer<T::session_key> &&
    std::semiregular<T::shared_secret> &&
    std::copyable<T::keychain> &&
    requires(ref<T::secret_key> sk, side s) {
        { T::keychain::initialize(sk, s) } ->
            std::same_as<std::optional<T::keychain>>;
    } &&
    requires(T::keychain const& kc) {
        { kc.pk() } -> std::convertible_to<T::public_key>;
    } &&
    requires(T::keychain const& kc, ref<T::public_key> pk) {
        { T::handshake(kc, pk) } ->
            std::same_as<std::optional<T::shared_secret>>;
    } &&
    requires(T::shared_secret secret) {
        { secret.rx_k } -> std::same_as<T::session_key>;
        { secret.tx_k } -> std::same_as<T::session_key>;
    };
// clang-format on

} // namespace ecstk::crypto::kx

#endif // H_7EF44563B1C6470B8FFFEFB77C5D88DF
