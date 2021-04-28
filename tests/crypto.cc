// Copyright(c) 2021 Nezametdinov E. Ildus.
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)
//
#include "../src/crypto_algorithm.hh"
#include "../src/crypto_stream_salsa.hh"
#include "../src/crypto_stream_xsalsa.hh"
#include "utils.hh"

#include <random>
#include <sodium.h>

////////////////////////////////////////////////////////////////////////////////
// Compile-time tests.
////////////////////////////////////////////////////////////////////////////////

namespace crypto = ecstk::crypto;

static_assert(crypto::stream::salsa::key::static_size() ==
              crypto_stream_salsa20_KEYBYTES);
static_assert(crypto::stream::salsa::nonce::static_size() ==
              crypto_stream_salsa20_NONCEBYTES);

static_assert(crypto::stream::xsalsa::key::static_size() ==
              crypto_stream_xsalsa20_KEYBYTES);
static_assert(crypto::stream::xsalsa::nonce::static_size() ==
              crypto_stream_xsalsa20_NONCEBYTES);

static_assert(crypto::stream::cipher<crypto::stream::salsa::cipher<20>>);
static_assert(crypto::stream::cipher<crypto::stream::xsalsa::cipher<20>>);

////////////////////////////////////////////////////////////////////////////////
// Additional utility components.
////////////////////////////////////////////////////////////////////////////////

template <ecstk::static_byte_buffer Buffer>
void
sodium_randomize(Buffer& b) noexcept {
    randombytes_buf(b.data(), b.size());
}

namespace detail {

static constexpr auto salsa20_block_size = crypto::stream::salsa::block_size;

template <ecstk::static_byte_buffer Buffer>
constexpr auto n_salsa20_blocks =
    std::size_t{(Buffer::static_size() / salsa20_block_size) +
                ((Buffer::static_size() % salsa20_block_size) != 0)};

} // namespace detail

/*
namespace crypto_connection_tests {
namespace ecs = ::ecs;
namespace std = ::std;
namespace crypto = ecs::crypto;

using ecs::ref;

static constexpr auto packet_size = std::size_t{500};
static constexpr auto counter_size = sizeof(std::uint64_t);

ecs::buffer<packet_size> client_msg_buf{};
ecs::buffer<packet_size> server_msg_buf{};

struct bridge;

using connection_base =
    crypto::connection_base<counter_size, packet_size, bridge>;

using connection_client =
    crypto::connection_client<counter_size, packet_size, bridge>;

using connection_server =
    crypto::connection_server<counter_size, packet_size, bridge>;

using rx_counter = connection_base::rx_counter;
using tx_counter = connection_base::tx_counter;

using rx_payload = connection_base::rx_payload;
using tx_payload = connection_base::tx_payload;

using rx_message = connection_base::rx_message;
using tx_message = connection_base::tx_message;

struct bridge {
    auto
    rx(ref<rx_counter> i, ref<rx_payload> x) noexcept -> bool {
        if(is_verbose) {
            std::cout << (is_server ? "[server] " : "[client] ");
            std::cout << "rx:\n";
            std::cout << "counter:\n";
            print(i);
            std::cout << "payload:\n";
            print(x);
        }

        return true;
    }

    auto
    accept(ref<crypto::pk_auth::public_key> pk) noexcept -> bool {
        if(is_verbose) {
            std::cout << "[server] client connected:\n";
            print(pk);
        }

        return true;
    }

    auto
    signal_session_start() noexcept -> bool {
        if(is_verbose) {
            std::cout << (is_server ? "[server] " : "[client] ");
            std::cout << "session started\n";
        }

        return true;
    }

    template <typename Tx_completion_handler>
    auto
    tx(ref<tx_message> x, Tx_completion_handler h) noexcept -> bool {
        auto& msg_buf = (is_server ? server_msg_buf : client_msg_buf);

        x.copy_into(msg_buf);

        if(is_verbose) {
            std::cout << (is_server ? "[server] " : "[client] ");
            std::cout << "sending:\n";
            print(msg_buf);
        }

        return h();
    }

    bool is_verbose;
    bool is_server;
};

auto
rx(connection_client& c) {
    return c.rx(server_msg_buf.template view_as<rx_message>());
}

auto
rx(connection_server& c) {
    return c.rx(client_msg_buf.template view_as<rx_message>());
}

} // namespace crypto_connection_tests

*/

////////////////////////////////////////////////////////////////////////////////
// Runtime tests.
////////////////////////////////////////////////////////////////////////////////

int
main() {
    std::cout << "============================================================="
                 "===================\n"
              << "Initialization (libsodium)\n"
              << "============================================================="
                 "===================\n";

    validate(sodium_init() == 0);

    std::cout << "============================================================="
                 "===================\n"
              << "Secure comparison (constant-time)\n"
              << "============================================================="
                 "===================\n";

    if(true) {
        unsigned char a[] = "JDHCSKS";
        unsigned char b[] = "DJCJJCS";
        unsigned char c[] = "JDHCSKS";
        unsigned char d[] = "JDHCSKM";
        unsigned char e[] = "JDHCSKMMMM";

        std::cout << "a and b:\n";
        validate(crypto::equals(a, b) == false);

        std::cout << "a and c:\n";
        validate(crypto::equals(a, c) == true);

        std::cout << "c and d:\n";
        validate(crypto::equals(c, d) == false);

        std::cout << "d and e:\n";
        validate(crypto::equals(d, e) == false);
    }

    std::cout << "============================================================="
                 "===================\n"
              << "Secure increment (constant-time)\n"
              << "============================================================="
                 "===================\n";

    if(true) {
        using integer_buffer = crypto::stream::xsalsa::nonce;

        auto n = integer_buffer{};
        auto expected_n = integer_buffer{0xE8, 0x03};

        for(int i = 0; i < 1000; ++i) {
            crypto::increment(n);
        }

        std::cout << "n:\n";
        print(n);
        std::cout << "expected n:\n";
        print(expected_n);
        validate(equal(n, expected_n));
    }

    std::cout << "============================================================="
                 "===================\n"
              << "Salsa20 - PRG\n"
              << "============================================================="
                 "===================\n";

    if(true) {
        using cipher = crypto::stream::salsa::cipher<20>;
        using data_buf = ecstk::buffer<1023>;

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "initialization\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        auto key = cipher::key{};
        sodium_randomize(key);
        std::cout << "key:\n";
        print(key);

        auto nonce = cipher::nonce{};
        sodium_randomize(nonce);
        std::cout << "nonce:\n";
        print(nonce);

        std::cout << "counter: 0\n";

        auto c = cipher{key, nonce, 0};

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "generation [pass 0]\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            auto buf = data_buf{};
            auto buf_sodium = data_buf{};

            std::cout << "preparing buffers\n";
            validate(equal(buf, buf_sodium));

            c.generate(buf);
            std::cout << "generated data:\n";
            print(buf);

            crypto_stream_salsa20_xor_ic(buf_sodium.data(), buf_sodium.data(),
                                         buf_sodium.size(), nonce.data(), 0,
                                         key.data());
            std::cout << "generated data [libsodium]:\n";
            print(buf_sodium);

            validate(equal(buf, buf_sodium));
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "generation [pass 1] - new nonce and counter\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        sodium_randomize(nonce);
        c.set_nonce(nonce);
        std::cout << "nonce:\n";
        print(nonce);

        static constexpr auto counter = std::uint64_t{0x00000000FFFFFFFAULL};

        c.set_counter(counter);
        std::cout << "counter:\n" << c.counter() << '\n';
        validate(c.counter() == counter);

        if(true) {
            auto buf = data_buf{};
            auto buf_sodium = data_buf{};
            std::cout << "preparing buffers\n";
            validate(equal(buf, buf_sodium));

            c.generate(buf);
            std::cout << "generated data:\n";
            print(buf);

            crypto_stream_salsa20_xor_ic(buf_sodium.data(), buf_sodium.data(),
                                         buf_sodium.size(), nonce.data(),
                                         counter, key.data());
            std::cout << "generated data [libsodium]:\n";
            print(buf_sodium);

            validate(equal(buf, buf_sodium));
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "generation [pass 2] - natural counter increment\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            auto buf = data_buf{};
            auto buf_sodium = data_buf{};
            std::cout << "preparing buffers\n";
            validate(equal(buf, buf_sodium));

            c.generate(buf);
            std::cout << "generated data:\n";
            print(buf);

            crypto_stream_salsa20_xor_ic(
                buf_sodium.data(), buf_sodium.data(), buf_sodium.size(),
                nonce.data(), counter + detail::n_salsa20_blocks<data_buf>,
                key.data());
            std::cout << "generated data [libsodium]:\n";
            print(buf_sodium);

            validate(equal(buf, buf_sodium));

            std::cout << "counter - posterior:\n" << c.counter() << '\n';
            validate(c.counter() ==
                     (counter + 2 * detail::n_salsa20_blocks<data_buf>));
        }
    }

    std::cout << "============================================================="
                 "===================\n"
              << "Salsa20 - XOR\n"
              << "============================================================="
                 "===================\n";

    if(true) {
        using cipher = crypto::stream::salsa::cipher<20>;
        using data_buf = ecstk::buffer<1023>;

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "initialization\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        auto key = cipher::key{};
        sodium_randomize(key);
        std::cout << "key:\n";
        print(key);

        auto nonce = cipher::nonce{};
        sodium_randomize(nonce);
        std::cout << "nonce:\n";
        print(nonce);

        std::cout << "counter: 0\n";

        auto data = data_buf{};
        sodium_randomize(data);
        std::cout << "data:\n";
        print(data);

        auto c = cipher{key, nonce, 0};

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "encryption [pass 0]\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            auto enc = data;
            auto enc_sodium = data;
            std::cout << "preparing buffers\n";
            validate(equal(enc, enc_sodium) && equal(enc, data));

            c.xor_buf(enc);
            std::cout << "encrypted data:\n";
            print(enc);

            crypto_stream_salsa20_xor_ic(enc_sodium.data(), enc_sodium.data(),
                                         enc_sodium.size(), nonce.data(), 0,
                                         key.data());
            std::cout << "encrypted data [libsodium]:\n";
            print(enc_sodium);

            validate(equal(enc, enc_sodium) && !equal(enc, data));
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "encryption [pass 1] - new nonce and counter\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        sodium_randomize(nonce);
        c.set_nonce(nonce);
        std::cout << "nonce:\n";
        print(nonce);

        static constexpr auto counter = std::uint64_t{0x00000000FFFFFFFAULL};

        c.set_counter(counter);
        std::cout << "counter:\n" << c.counter() << '\n';
        validate(c.counter() == counter);

        if(true) {
            auto enc = data;
            auto enc_sodium = data;
            std::cout << "preparing buffers\n";
            validate(equal(enc, enc_sodium) && equal(enc, data));

            c.xor_buf(enc);
            std::cout << "encrypted data:\n";
            print(enc);

            crypto_stream_salsa20_xor_ic(enc_sodium.data(), enc_sodium.data(),
                                         enc_sodium.size(), nonce.data(),
                                         counter, key.data());
            std::cout << "encrypted data [libsodium]:\n";
            print(enc_sodium);

            validate(equal(enc, enc_sodium) && !equal(enc, data));
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "encryption [pass 2] - natural counter increment\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            auto enc = data;
            auto enc_sodium = data;
            std::cout << "preparing buffers\n";
            validate(equal(enc, enc_sodium) && equal(enc, data));

            c.xor_buf(enc);
            std::cout << "encrypted data:\n";
            print(enc);

            crypto_stream_salsa20_xor_ic(
                enc_sodium.data(), enc_sodium.data(), enc_sodium.size(),
                nonce.data(), counter + detail::n_salsa20_blocks<data_buf>,
                key.data());
            std::cout << "encrypted data [libsodium]:\n";
            print(enc_sodium);

            validate(equal(enc, enc_sodium) && !equal(enc, data));

            std::cout << "counter - posterior:\n" << c.counter() << '\n';
            validate(c.counter() ==
                     (counter + 2 * detail::n_salsa20_blocks<data_buf>));
        }
    }

    std::cout << "============================================================="
                 "===================\n"
              << "XSalsa20 - PRG\n"
              << "============================================================="
                 "===================\n";

    if(true) {
        using cipher = crypto::stream::xsalsa::cipher<20>;
        using data_buf = ecstk::buffer<1023>;

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "initialization\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        auto key = cipher::key{};
        sodium_randomize(key);
        std::cout << "key:\n";
        print(key);

        auto nonce = cipher::nonce{};
        sodium_randomize(nonce);
        std::cout << "nonce:\n";
        print(nonce);

        std::cout << "counter: 0\n";

        auto c = cipher{key, nonce, 0};

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "generation [pass 0]\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            auto buf = data_buf{};
            auto buf_sodium = data_buf{};

            std::cout << "preparing buffers\n";
            validate(equal(buf, buf_sodium));

            c.generate(buf);
            std::cout << "generated data:\n";
            print(buf);

            crypto_stream_xsalsa20_xor_ic(buf_sodium.data(), buf_sodium.data(),
                                          buf_sodium.size(), nonce.data(), 0,
                                          key.data());
            std::cout << "generated data [libsodium]:\n";
            print(buf_sodium);

            validate(equal(buf, buf_sodium));
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "generation [pass 1] - new nonce and counter\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        sodium_randomize(nonce);
        c.set_nonce(nonce);
        std::cout << "nonce:\n";
        print(nonce);

        static constexpr auto counter = std::uint64_t{0x00000000FFFFFFFAULL};

        c.set_counter(counter);
        std::cout << "counter:\n" << c.counter() << '\n';
        validate(c.counter() == counter);

        if(true) {
            auto buf = data_buf{};
            auto buf_sodium = data_buf{};
            std::cout << "preparing buffers\n";
            validate(equal(buf, buf_sodium));

            c.generate(buf);
            std::cout << "generated data:\n";
            print(buf);

            crypto_stream_xsalsa20_xor_ic(buf_sodium.data(), buf_sodium.data(),
                                          buf_sodium.size(), nonce.data(),
                                          counter, key.data());
            std::cout << "generated data [libsodium]:\n";
            print(buf_sodium);

            validate(equal(buf, buf_sodium));
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "generation [pass 2] - natural counter increment\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            auto buf = data_buf{};
            auto buf_sodium = data_buf{};
            std::cout << "preparing buffers\n";
            validate(equal(buf, buf_sodium));

            c.generate(buf);
            std::cout << "generated data:\n";
            print(buf);

            crypto_stream_xsalsa20_xor_ic(
                buf_sodium.data(), buf_sodium.data(), buf_sodium.size(),
                nonce.data(), counter + detail::n_salsa20_blocks<data_buf>,
                key.data());
            std::cout << "generated data [libsodium]:\n";
            print(buf_sodium);

            validate(equal(buf, buf_sodium));

            std::cout << "counter - posterior:\n" << c.counter() << '\n';
            validate(c.counter() ==
                     (counter + 2 * detail::n_salsa20_blocks<data_buf>));
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "generation [pass 3] - copy cipher state and reset counter\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            auto buf = data_buf{};
            auto buf_sodium = data_buf{};
            std::cout << "preparing buffers\n";
            validate(equal(buf, buf_sodium));

            auto c1 = c;
            c1.set_counter(0);
            c1.generate(buf);
            std::cout << "generated data:\n";
            print(buf);

            crypto_stream_xsalsa20_xor(buf_sodium.data(), buf_sodium.data(),
                                       buf_sodium.size(), nonce.data(),
                                       key.data());
            std::cout << "generated data [libsodium]:\n";
            print(buf_sodium);

            validate(equal(buf, buf_sodium));
        }
    }

    std::cout << "============================================================="
                 "===================\n"
              << "XSalsa20 - XOR\n"
              << "============================================================="
                 "===================\n";

    if(true) {
        using cipher = crypto::stream::xsalsa::cipher<20>;
        using data_buf = ecstk::buffer<1023>;

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "initialization\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        auto key = cipher::key{};
        sodium_randomize(key);
        std::cout << "key:\n";
        print(key);

        auto nonce = cipher::nonce{};
        sodium_randomize(nonce);
        std::cout << "nonce:\n";
        print(nonce);

        std::cout << "counter: 0\n";

        auto data = data_buf{};
        sodium_randomize(data);
        std::cout << "data:\n";
        print(data);

        auto c = cipher{key, nonce, 0};

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "encryption [pass 0]\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            auto enc = data;
            auto enc_sodium = data;
            std::cout << "preparing buffers\n";
            validate(equal(enc, enc_sodium) && equal(enc, data));

            c.xor_buf(enc);
            std::cout << "encrypted data:\n";
            print(enc);

            crypto_stream_xsalsa20_xor_ic(enc_sodium.data(), enc_sodium.data(),
                                          enc_sodium.size(), nonce.data(), 0,
                                          key.data());
            std::cout << "encrypted data [libsodium]:\n";
            print(enc_sodium);

            validate(equal(enc, enc_sodium) && !equal(enc, data));
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "encryption [pass 1] - new nonce and counter\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        sodium_randomize(nonce);
        c.set_nonce(nonce);
        std::cout << "nonce:\n";
        print(nonce);

        static constexpr auto counter = std::uint64_t{0x00000000FFFFFFFAULL};

        c.set_counter(counter);
        std::cout << "counter:\n" << c.counter() << '\n';
        validate(c.counter() == counter);

        if(true) {
            auto enc = data;
            auto enc_sodium = data;
            std::cout << "preparing buffers\n";
            validate(equal(enc, enc_sodium) && equal(enc, data));

            c.xor_buf(enc);
            std::cout << "encrypted data:\n";
            print(enc);

            crypto_stream_xsalsa20_xor_ic(enc_sodium.data(), enc_sodium.data(),
                                          enc_sodium.size(), nonce.data(),
                                          counter, key.data());
            std::cout << "encrypted data [libsodium]:\n";
            print(enc_sodium);

            validate(equal(enc, enc_sodium) && !equal(enc, data));
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "encryption [pass 2] - natural counter increment\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            auto enc = data;
            auto enc_sodium = data;
            std::cout << "preparing buffers\n";
            validate(equal(enc, enc_sodium) && equal(enc, data));

            c.xor_buf(enc);
            std::cout << "encrypted data:\n";
            print(enc);

            crypto_stream_xsalsa20_xor_ic(
                enc_sodium.data(), enc_sodium.data(), enc_sodium.size(),
                nonce.data(), counter + detail::n_salsa20_blocks<data_buf>,
                key.data());
            std::cout << "encrypted data [libsodium]:\n";
            print(enc_sodium);

            validate(equal(enc, enc_sodium) && !equal(enc, data));

            std::cout << "counter - posterior:\n" << c.counter() << '\n';
            validate(c.counter() ==
                     (counter + 2 * detail::n_salsa20_blocks<data_buf>));
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "encryption [pass 3] - copy cipher state and reset counter\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            auto enc = data;
            auto enc_sodium = data;
            std::cout << "preparing buffers\n";
            validate(equal(enc, enc_sodium) && equal(enc, data));

            auto c1 = c;
            c1.set_counter(0);
            c1.xor_buf(enc);
            std::cout << "encrypted data:\n";
            print(enc);

            crypto_stream_xsalsa20_xor(enc_sodium.data(), enc_sodium.data(),
                                       enc_sodium.size(), nonce.data(),
                                       key.data());
            std::cout << "encrypted data [libsodium]:\n";
            print(enc_sodium);

            validate(equal(enc, enc_sodium) && !equal(enc, data));
        }
    }

    /*
    std::cout << "============================================================="
                 "===================\n"
              << "Poly1305\n"
              << "============================================================="
                 "===================\n";

    if(true) {
        using mac = crypto::poly1305;
        using buffer = ecs::buffer<1023>;
        using buffer_part0 = ecs::buffer<517>;
        using buffer_part1 = ecs::buffer<506>;

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "initialization\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        auto key = mac::key{};
        sodium_randomize(key);
        std::cout << "key:\n";
        print(key);

        auto data = buffer{};
        sodium_randomize(data);
        std::cout << "data:\n";
        print(data);

        auto [data_part0, data_part1] =
            data.extract<buffer_part0, buffer_part1>();
        std::cout << "data (part 0):\n";
        print(data_part0);
        std::cout << "data (part 1):\n";
        print(data_part1);
        validate(equal(data, join_buffers_secure(data_part0, data_part1)));

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "MAC computation\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        auto tag = mac::generate(key, data);
        std::cout << "tag:\n";
        print(tag);

        auto tag_multi = mac::generate(key, data_part0, data_part1);
        std::cout << "tag [multipart]:\n";
        print(tag_multi);
        validate(equal(tag, tag_multi));

        auto tag_sodium = mac::tag{};
        crypto_onetimeauth(
            tag_sodium.data(), data.data(), data.size(), key.data());
        std::cout << "tag [libsodium]:\n";
        print(tag_sodium);

        validate(equal(tag, tag_sodium));
    }

    std::cout << "============================================================="
                 "===================\n"
              << "AEAD\n"
              << "============================================================="
                 "===================\n";

    if(true) {
        static constexpr auto meta_size = std::size_t{5};
        static constexpr auto packet_size = std::size_t{560};
        static constexpr auto counter_size = sizeof(std::uint64_t);

        using xsalsa = crypto::xsalsa<20>;

        using aead = crypto::aead<meta_size, counter_size, packet_size, int>;
        using secure_prng = crypto::prng;

        static_assert(std::same_as<secure_prng::seed, xsalsa::key>);
        static_assert(std::same_as<secure_prng::nonce, xsalsa::nonce>);

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "initialization\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        auto const data =
            aead::secret_data{'A', 'B', 'C', 'D', 'E', 22, 33, 44, 55,  66, 10,
                              20,  30,  40,  50,  60,  70, 80, 90, 100, 110};
        std::cout << "data:\n";
        print(data);

        auto prng_seed = secure_prng::seed{};
        sodium_randomize(prng_seed);
        std::cout << "secure PRNG seed:\n";
        print(prng_seed);

        auto key0 = aead::cipher::key{};
        auto key1 = aead::cipher::key{};
        sodium_randomize(key0);
        sodium_randomize(key1);
        std::cout << "keychain:\n";
        print(key0);
        print(key1);

        auto kc = aead::keychain{key0, key1};
        auto prng = secure_prng{prng_seed};

        auto prng_sodium = [c = std::uint64_t{},
                            prng_nonce = secure_prng::nonce{},
                            prng_seed]() mutable {
            aead::nonce n{};
            crypto_stream_xsalsa20_xor_ic(n.data(), n.data(), n.size(),
                                          prng_nonce.data(), c++,
                                          prng_seed.data());

            return n;
        };

        auto aead_encrypt_sodium = [key0, key1, &prng_sodium](
                                       aead::associated_data meta,
                                       aead::counter i,
                                       aead::secret_data data) {
            auto n = prng_sodium();
            auto mac_key = crypto::poly1305::key{};
            auto mac_tag = crypto::poly1305::tag{};

            auto enc = join_buffers(i, data);

            // encrypt
            crypto_stream_xsalsa20_xor(
                enc.data(), enc.data(), enc.size(), n.data(), key0.data());

            crypto_stream_xsalsa20(
                mac_key.data(), mac_key.size(), n.data(), key1.data());

            // mac
            if(true) {
                crypto_onetimeauth_state state;
                crypto_onetimeauth_init(&state, mac_key.data());

                crypto_onetimeauth_update(&state, meta.data(), meta.size());
                crypto_onetimeauth_update(&state, n.data(), n.size());
                crypto_onetimeauth_update(&state, enc.data(), enc.size());
                crypto_onetimeauth_final(&state, mac_tag.data());
            }

            auto m = aead::message{};
            m.fill_from(n, enc, mac_tag);

            return m;
        };

        for(std::size_t i = 0; i < 5; ++i) {
            std::cout << "-----------------------------------------------------"
                         "--------"
                         "-------------------\n"
                      << "encrypting [pass " << i << "]\n"
                      << "-----------------------------------------------------"
                         "--------"
                         "-------------------\n";

            auto meta = aead::associated_data{};
            sodium_randomize(meta);
            std::cout << "associated data:\n";
            print(meta);

            auto counter = aead::counter{};
            ecs::int_to_buffer(std::uint64_t{i}, counter);
            std::cout << "counter:\n";
            print(counter);

            std::cout << "encrypted message:\n";
            auto enc = aead::encrypt(
                kc, meta,
                prng.generate().template extract<aead::cipher::nonce>(),
                counter, data);
            print(enc);

            std::cout << "encrypted message [libsodium]:\n";
            auto enc_sodium = aead_encrypt_sodium(meta, counter, data);
            print(enc_sodium);

            validate(equal(enc, enc_sodium));

            std::cout << "-----------------------------------------------------"
                         "--------"
                         "-------------------\n"
                      << "decrypting [pass " << i << "]\n"
                      << "-----------------------------------------------------"
                         "--------"
                         "-------------------\n";

            if(auto decryption_result = aead::decrypt(kc, meta, enc); true) {
                validate(decryption_result.has_value());

                std::cout << "decrypted counter:\n";
                print(decryption_result->i);
                std::cout << "decrypted data:\n";
                print(decryption_result->data);

                validate(equal(decryption_result->i, counter) &&
                         equal(decryption_result->data, data));
            }

            std::cout << "breaking encrypted message\n";
            enc[0] ^= 0xEB;
            enc[enc.size() - 1] ^= 0x3A;
            std::cout << "broken encrypted message:\n";
            print(enc);

            std::cout << "decrypting broken message\n";
            if(auto decryption_result = aead::decrypt(kc, meta, enc); true) {
                if(decryption_result) {
                    std::cout << "successfully decrypted\n";
                } else {
                    std::cout << "could not decrypt\n";
                }

                validate(!decryption_result);
            }

            std::cout << "decrypting message using broken associated data\n";
            if(auto decryption_result0 = aead::decrypt(kc, meta, enc_sodium);
               true) {
                std::cout << "broken associated data:\n";
                meta[0] ^= 0xAE;
                print(meta);

                auto decryption_result1 = aead::decrypt(kc, meta, enc_sodium);
                if(decryption_result1) {
                    std::cout << "successfully decrypted\n";
                } else {
                    std::cout << "could not decrypt\n";
                }

                validate(decryption_result0 && !decryption_result1 &&
                         equal(decryption_result0->i, counter) &&
                         equal(decryption_result0->data, data));
            }
        }
    }

    std::cout << "============================================================="
                 "===================\n"
              << "Key exchange\n"
              << "============================================================="
                 "===================\n";

    if(true) {
        using kx = crypto::kx;

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "initialization\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        auto sk0 = kx::secret_key{};
        auto sk1 = kx::secret_key{};
        sodium_randomize(sk0);
        sodium_randomize(sk1);
        std::cout << "secret keys:\n";
        print(sk0);
        print(sk1);

        std::cout << "initializing keychains:\n";
        auto kc0 = kx::keychain::initialize(sk0, kx::side::client);
        auto kc1 = kx::keychain::initialize(sk1, kx::side::server);
        validate(kc0 && kc1);

        std::cout << "client pk and sk:\n";
        print(kc0->get_public_key());
        print(kc0->get_secret_key());

        std::cout << "server pk and sk:\n";
        print(kc1->get_public_key());
        print(kc1->get_secret_key());

        auto peer_pk0 = kc1->get_public_key().view_as<kx::peer_public_key>();
        auto peer_pk1 = kc0->get_public_key().view_as<kx::peer_public_key>();

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "session key computation\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        std::cout << "computing session keys on both sides\n";
        auto s0 = kx::generate_session_keys(*kc0, peer_pk0);
        auto s1 = kx::generate_session_keys(*kc1, peer_pk1);
        validate(s0 && s1);

        std::cout << "client session keys:\n";
        print(s0->rx_k);
        print(s0->tx_k);

        std::cout << "server session keys:\n";
        print(s1->rx_k);
        print(s1->tx_k);

        validate(equal(s0->rx_k, s1->tx_k) && equal(s0->tx_k, s1->rx_k));

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "session key computation [libsodium]\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            auto s0_sodium = kx::session{};
            auto s1_sodium = kx::session{};

            std::cout << "computing session keys on both sides\n";
            validate(
                (crypto_kx_client_session_keys(
                     s0_sodium.rx_k.data(), s0_sodium.tx_k.data(),
                     kc0->get_public_key().data(), kc0->get_secret_key().data(),
                     kc1->get_public_key().data()) == 0) &&
                (crypto_kx_server_session_keys(
                     s1_sodium.rx_k.data(), s1_sodium.tx_k.data(),
                     kc1->get_public_key().data(), kc1->get_secret_key().data(),
                     kc0->get_public_key().data()) == 0));

            std::cout << "client session keys:\n";
            print(s0_sodium.rx_k);
            print(s0_sodium.tx_k);

            std::cout << "server session keys:\n";
            print(s1_sodium.rx_k);
            print(s1_sodium.tx_k);

            validate(equal(s0_sodium.rx_k, s0->rx_k) &&
                     equal(s0_sodium.tx_k, s0->tx_k) &&
                     equal(s1_sodium.rx_k, s1->rx_k) &&
                     equal(s1_sodium.tx_k, s1->tx_k));
        }
    }

    std::cout << "============================================================="
                 "===================\n"
              << "Public-key signatures\n"
              << "============================================================="
                 "===================\n";

    if(true) {
        using auth = crypto::pk_auth;
        using buffer = ecs::buffer<2048>;
        using buffer_part0 = ecs::buffer<521>;
        using buffer_part1 = ecs::buffer<379>;
        using buffer_part2 = ecs::buffer<723>;
        using buffer_part3 = ecs::buffer<425>;

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "initialization\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        auto kc_seed = auth::secret_key{};
        sodium_randomize(kc_seed);
        std::cout << "keychain seed (secret key):\n";
        print(kc_seed);

        auto data = buffer{};
        sodium_randomize(data);
        std::cout << "data:\n";
        print(data);

        auto [data_part0, data_part1, data_part2, data_part3] =
            data.extract<buffer_part0, buffer_part1, buffer_part2,
                         buffer_part3>();
        std::cout << "data (part 0):\n";
        print(data_part0);
        std::cout << "data (part 1):\n";
        print(data_part1);
        std::cout << "data (part 2):\n";
        print(data_part2);
        std::cout << "data (part 3):\n";
        print(data_part3);
        validate(equal(data, join_buffers_secure(data_part0, data_part1,
                                                 data_part2, data_part3)));

        std::cout << "initializing keychain:\n";
        auto kc = auth::keychain::initialize(kc_seed);
        validate(kc.has_value());

        std::cout << "public and secret keys:\n";
        auto& pk = kc->get_public_key();
        // Note: sodium uses keypair [secret_key | public_key] as a secret key.
        auto& sk = kc->get_keypair();
        print(pk);
        print(sk);

        std::cout << "initializing keychain [libsodium]:\n";
        if(true) {
            unsigned char sodium_pk[crypto_sign_PUBLICKEYBYTES]{};
            unsigned char sodium_sk[crypto_sign_SECRETKEYBYTES]{};

            crypto_sign_seed_keypair(sodium_pk, sodium_sk, kc_seed.data());
            validate(equal(pk, sodium_pk) && equal(sk, sodium_sk));
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "signing\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        auto sig = auth::sign(*kc, data);
        std::cout << "signature:\n";
        print(sig);

        std::cout << "signature [multipart]:\n";
        if(true) {
            auto sig_multi =
                auth::sign(*kc, data_part0, data_part1, data_part2, data_part3);
            print(sig_multi);

            validate(equal(sig, sig_multi));
        }

        std::cout << "signature [libsodium]:\n";
        if(true) {
            auto sodium_sig = ecs::buffer<crypto_sign_BYTES>{};

            crypto_sign_detached(sodium_sig.data(), nullptr, data.data(),
                                 data.size(), sk.data());
            print(sodium_sig);

            validate(equal(sig, sodium_sig));
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "verification\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        std::cout << "verifying valid signature:\n";
        validate(auth::verify(kc->get_public_key(), sig, data));

        if(true) {
            std::cout << "verifying valid signature [multipart]:\n";
            validate(auth::verify(kc->get_public_key(), sig, data_part0,
                                  data_part1, data_part2, data_part3));
        }

        if(true) {
            std::cout << "verifying valid signature [libsodium]:\n";
            validate(crypto_sign_verify_detached(
                         sig.data(), data.data(), data.size(), pk.data()) == 0);
        }

        std::cout << "breaking signature\n";
        sig[0] ^= 0xAE;
        std::cout << "broken signature:\n";
        print(sig);

        std::cout << "verifying broken signature:\n";
        validate(!auth::verify(kc->get_public_key(), sig, data));

        if(true) {
            std::cout << "verifying broken signature [multipart]:\n";
            validate(!auth::verify(kc->get_public_key(), sig, data_part0,
                                   data_part1, data_part2, data_part3));
        }

        if(true) {
            std::cout << "verifying broken signature [libsodium]:\n";
            validate(crypto_sign_verify_detached(
                         sig.data(), data.data(), data.size(), pk.data()) != 0);
        }
    }

    std::cout << "============================================================="
                 "===================\n"
              << "Connection\n"
              << "============================================================="
                 "===================\n";

    if(true) {
        using kx = crypto::kx;
        using auth = crypto::pk_auth;
        using secure_prng = crypto::prng;

        using crypto_connection_tests::bridge;

        using crypto_connection_tests::connection_client;
        using crypto_connection_tests::connection_server;

        using crypto_connection_tests::rx_counter;
        using crypto_connection_tests::tx_counter;

        using crypto_connection_tests::rx_payload;
        using crypto_connection_tests::tx_payload;

        using crypto_connection_tests::rx_message;
        using crypto_connection_tests::tx_message;

        using crypto_connection_tests::rx;
        using rx_result = crypto_connection_tests::connection_base::rx_result;

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "verbose\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            auto prng_seed0 = secure_prng::seed{};
            auto prng_seed1 = secure_prng::seed{};
            sodium_randomize(prng_seed0);
            sodium_randomize(prng_seed1);
            std::cout << "secure PRNG seeds (client and server):\n";
            print(prng_seed0);
            print(prng_seed1);

            auto auth_sk0 = auth::secret_key{};
            auto auth_sk1 = auth::secret_key{};
            sodium_randomize(auth_sk0);
            sodium_randomize(auth_sk1);
            std::cout << "secret keys (client and server):\n";
            print(auth_sk0);
            print(auth_sk1);

            std::cout << "initializing client's and server's keychains:\n";
            auto kc0 = auth::keychain::initialize(auth_sk0);
            auto kc1 = auth::keychain::initialize(auth_sk1);
            validate(kc0.has_value() && kc1.has_value());

            std::cout << "client's public and secret keys:\n";
            print(kc0->get_public_key());
            print(kc0->get_secret_key());

            std::cout << "server's public and secret keys:\n";
            print(kc1->get_public_key());
            print(kc1->get_secret_key());

            auto bridge_client = bridge{.is_verbose = true, .is_server = false};
            auto bridge_server = bridge{.is_verbose = true, .is_server = true};

            auto client = connection_client{prng_seed0, *kc0, bridge_client};
            auto server = connection_server{prng_seed1, *kc1, bridge_server};

            std::cout << "[client] starting handshake\n";
            validate(client.start_handshake(kc1->get_public_key()));

            std::cout << "[server] receiving handshake 0\n";
            validate(rx(server) == rx_result::handshake);

            std::cout << "[client] receiving handshake 1\n";
            validate(rx(client) == rx_result::handshake);

            std::cout << "[server] receiving handshake 2\n";
            validate(rx(server) == rx_result::handshake);

            auto payload = tx_payload{'A', 'B', 'C', 'D', 'E', 0, 1,   2,  3,
                                      4,   5,   6,   7,   8,   9, 255, 100};
            for(auto i = std::uint64_t{}; i < 2; ++i) {
                auto ic = tx_counter{};
                int_to_buffer(i, ic);

                std::cout << "[client] sending payload\n";
                validate(client.tx(ic, payload, []() {
                    std::cout << "[client] sending complete\n";
                    return true;
                }));

                std::cout << "[server] sending payload\n";
                validate(server.tx(ic, payload, []() {
                    std::cout << "[server] sending complete\n";
                    return true;
                }));

                std::cout << "[client] receiving payload\n";
                validate(rx(client) == rx_result::payload);

                std::cout << "[server] receiving payload\n";
                validate(rx(server) == rx_result::payload);
            }
        }

        std::cout
            << "-------------------------------------------------------------"
               "-------------------\n"
            << "silent (multiple iterations)\n"
            << "-------------------------------------------------------------"
               "-------------------\n";

        if(true) {
            using uniform = std::uniform_int_distribution<std::size_t>;
            static constexpr auto nonce_size = std::size_t{32};
            static constexpr auto n_iterations = 2000U;

            auto rd = std::random_device{};
            auto re = std::default_random_engine{rd()};

            // Distributions for choosing index of failure for each phase of the
            // handshake protocol.
            auto gen_corrupt = uniform{0, 1};
            uniform gen_corrupt_i[] = {
                uniform{0, auth::public_key::size() + nonce_size +
                               auth::signature::size() - 1},
                uniform{0, kx::public_key::size() + nonce_size +
                               auth::signature::size() - 1},
                uniform{
                    0, kx::public_key::size() + auth::signature::size() - 1}};

            unsigned n_negatives[] = {0, 0, 0};
            unsigned failed_i = std::numeric_limits<unsigned>::max(),
                     failed_j = failed_i;

            auto success = true;
            for(unsigned i = 0; i < n_iterations; ++i) {
                auto prng_seed0 = secure_prng::seed{};
                auto prng_seed1 = secure_prng::seed{};
                sodium_randomize(prng_seed0);
                sodium_randomize(prng_seed1);

                auto auth_sk0 = auth::secret_key{};
                auto auth_sk1 = auth::secret_key{};
                sodium_randomize(auth_sk0);
                sodium_randomize(auth_sk1);

                auto kc0 = auth::keychain::initialize(auth_sk0);
                auto kc1 = auth::keychain::initialize(auth_sk1);
                if(!(kc0.has_value() && kc1.has_value())) {
                    std::cout << "failed to initialize keychains\n";

                    success = false;
                    failed_i = i;
                    break;
                }

                auto bridge_client =
                    bridge{.is_verbose = false, .is_server = false};
                auto bridge_server =
                    bridge{.is_verbose = false, .is_server = true};

                auto client =
                    connection_client{prng_seed0, *kc0, bridge_client};
                auto server =
                    connection_server{prng_seed1, *kc1, bridge_server};

                if(!client.start_handshake(kc1->get_public_key())) {
                    std::cout << "failed to start handshake\n";

                    success = false;
                    failed_i = i;
                    break;
                }

                for(unsigned j = 0; j < 3; ++j) {
                    auto expected_result = rx_result::handshake;
                    if(gen_corrupt(re) == 0) {
                        using crypto_connection_tests::client_msg_buf;
                        using crypto_connection_tests::server_msg_buf;

                        expected_result = rx_result::handshake_failure;
                        n_negatives[j]++;

                        ((j == 1) ? server_msg_buf
                                  : client_msg_buf)[gen_corrupt_i[j](re)] ^=
                            0xAB;
                    }

                    if(j == 1) {
                        if(rx(client) != expected_result) {
                            success = false;
                        }
                    } else {
                        if(rx(server) != expected_result) {
                            success = false;
                        }
                    }

                    if(!success) {
                        failed_i = i;
                        failed_j = j;
                        break;
                    }

                    if(expected_result == rx_result::handshake_failure) {
                        break;
                    }
                }

                if(!success) {
                    break;
                }
            }

            std::cout << "number of iterations: " << n_iterations << '\n';
            std::cout << "number of expected failures due to corruption for "
                         "each handshake pass:\n";
            std::cout << "pass 0 (server receives client's greeting): "
                      << n_negatives[0] << '\n';
            std::cout << "pass 1 (client receives server's response): "
                      << n_negatives[1] << '\n';
            std::cout << "pass 2 (server receives client's response): "
                      << n_negatives[2] << '\n';
            std::cout << "failed iteration: " << failed_i << '\n';
            std::cout << "failed handshake pass: " << failed_j << '\n';
            validate(success);
        }
    }
    */

    std::cout << "============================================================="
                 "===================\n"
              << "Success\n"
              << "============================================================="
                 "===================\n";

    return EXIT_SUCCESS;
}
