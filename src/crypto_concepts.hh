// Copyright(c) 2021 Nezametdinov E. Ildus.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)
//
#ifndef H_7EF44563B1C6470B8FFFEFB77C5D88DF
#define H_7EF44563B1C6470B8FFFEFB77C5D88DF

#include "buffer.hh"
#include <optional>

namespace ecstk::crypto {
namespace std = ::std;

////////////////////////////////////////////////////////////////////////////////
// Key exchange schema concept.
////////////////////////////////////////////////////////////////////////////////

namespace kx {

// Side of the key exchange.
enum struct side { client, server };

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

} // namespace kx

////////////////////////////////////////////////////////////////////////////////
// Public key authentication schema concept.
////////////////////////////////////////////////////////////////////////////////

namespace pk_auth {

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

} // namespace pk_auth

////////////////////////////////////////////////////////////////////////////////
// PRG schema concept.
////////////////////////////////////////////////////////////////////////////////

namespace prg {

// clang-format off
template <typename T>
concept schema =
    static_byte_buffer<T::key> &&
    std::copyable<T> &&
    requires(ref<T::key> k) {
        T{k};
    } &&
    requires(T g, mut_byte_sequence buf) {
        { g.generate(buf) } -> std::same_as<void>;
    };
// clang-format on

} // namespace prg

////////////////////////////////////////////////////////////////////////////////
// Stream cipher concept.
////////////////////////////////////////////////////////////////////////////////

namespace stream {

// clang-format off
template <typename T>
concept cipher =
    static_byte_buffer<T::key> &&
    static_byte_buffer<T::nonce> &&
    std::copyable<T> &&
    requires(ref<T::key> k, ref<T::nonce> n) {
        T{k, n};
    } &&
    requires(T g, mut_byte_sequence buf) {
        { g.generate(buf) } -> std::same_as<void>;
        { g.xor_buf(buf) } -> std::same_as<void>;
    };
// clang-format on

} // namespace stream

} // namespace ecstk::crypto

#endif // H_7EF44563B1C6470B8FFFEFB77C5D88DF
