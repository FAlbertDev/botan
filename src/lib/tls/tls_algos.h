/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_ALGO_IDS_H_
#define BOTAN_TLS_ALGO_IDS_H_

#include <botan/asn1_obj.h>
#include <botan/pk_keys.h>
#include <botan/types.h>
#include <string>
#include <vector>

//BOTAN_FUTURE_INTERNAL_HEADER(tls_algos.h)

namespace Botan::TLS {

enum class Cipher_Algo {
   CHACHA20_POLY1305,

   AES_128_GCM,
   AES_256_GCM,

   AES_256_OCB,

   CAMELLIA_128_GCM,
   CAMELLIA_256_GCM,

   ARIA_128_GCM,
   ARIA_256_GCM,

   AES_128_CCM,
   AES_256_CCM,
   AES_128_CCM_8,
   AES_256_CCM_8,

   AES_128_CBC_HMAC_SHA1,
   AES_128_CBC_HMAC_SHA256,
   AES_256_CBC_HMAC_SHA1,
   AES_256_CBC_HMAC_SHA256,
   AES_256_CBC_HMAC_SHA384,

   DES_EDE_CBC_HMAC_SHA1,
};

enum class KDF_Algo {
   SHA_1,
   SHA_256,
   SHA_384,
};

std::string BOTAN_DLL kdf_algo_to_string(KDF_Algo algo);

enum class Nonce_Format {
   CBC_MODE,
   AEAD_IMPLICIT_4,
   AEAD_XOR_12,
};

// TODO encoding should match signature_algorithms extension
// TODO this should include hash etc as in TLS v1.3
enum class Auth_Method {
   RSA,
   ECDSA,

   // To support TLS 1.3 ciphersuites, which do not determine the auth method
   UNDEFINED,

   // These are placed outside the encodable range
   IMPLICIT = 0x10000
};

std::string BOTAN_TEST_API auth_method_to_string(Auth_Method method);
Auth_Method BOTAN_TEST_API auth_method_from_string(std::string_view str);

/*
* Matches with wire encoding
*/
enum class Group_Params : uint16_t {
   NONE = 0,

   SECP256R1 = 23,
   SECP384R1 = 24,
   SECP521R1 = 25,
   BRAINPOOL256R1 = 26,
   BRAINPOOL384R1 = 27,
   BRAINPOOL512R1 = 28,

   X25519 = 29,

   FFDHE_2048 = 256,
   FFDHE_3072 = 257,
   FFDHE_4096 = 258,
   FFDHE_6144 = 259,
   FFDHE_8192 = 260,

   // libOQS defines those in:
   // https://github.com/open-quantum-safe/oqs-provider/blob/main/oqs-template/oqs-kem-info.md
   KYBER_512_R3 = 0x023A,
   KYBER_768_R3 = 0x023C,
   KYBER_1024_R3 = 0x023D,

   // Cloudflare code points for hybrid PQC
   // https://blog.cloudflare.com/post-quantum-for-all/
   HYBRID_X25519_KYBER_512_R3_CLOUDFLARE = 0xFE30,
   HYBRID_X25519_KYBER_768_R3_CLOUDFLARE = 0xFE31,

   // libOQS defines those in:
   // https://github.com/open-quantum-safe/oqs-provider/blob/main/oqs-template/oqs-kem-info.md
   HYBRID_X25519_KYBER_512_R3_OQS = 0x2F39,
   HYBRID_X25519_KYBER_768_R3_OQS = 0x6399,

   HYBRID_SECP256R1_KYBER_512_R3_OQS = 0x2F3A,
   HYBRID_SECP384R1_KYBER_768_R3_OQS = 0x2F3C,
   HYBRID_SECP521R1_KYBER_1024_R3_OQS = 0x2F3D,
};

constexpr bool is_x25519(const Group_Params group) {
   return group == Group_Params::X25519;
}

constexpr bool is_ecdh(const Group_Params group) {
   return group == Group_Params::SECP256R1 || group == Group_Params::SECP384R1 || group == Group_Params::SECP521R1 ||
          group == Group_Params::BRAINPOOL256R1 || group == Group_Params::BRAINPOOL384R1 ||
          group == Group_Params::BRAINPOOL512R1;
}

constexpr bool is_dh(const Group_Params group) {
   return group == Group_Params::FFDHE_2048 || group == Group_Params::FFDHE_3072 || group == Group_Params::FFDHE_4096 ||
          group == Group_Params::FFDHE_6144 || group == Group_Params::FFDHE_8192;
}

constexpr bool is_pure_kyber(const Group_Params group) {
   return group == Group_Params::KYBER_512_R3 || group == Group_Params::KYBER_768_R3 ||
          group == Group_Params::KYBER_1024_R3;
}

constexpr bool is_hybrid(const Group_Params group) {
   return group == Group_Params::HYBRID_X25519_KYBER_512_R3_CLOUDFLARE ||
          group == Group_Params::HYBRID_X25519_KYBER_768_R3_CLOUDFLARE ||
          group == Group_Params::HYBRID_X25519_KYBER_512_R3_OQS ||
          group == Group_Params::HYBRID_X25519_KYBER_768_R3_OQS ||
          group == Group_Params::HYBRID_SECP256R1_KYBER_512_R3_OQS ||
          group == Group_Params::HYBRID_SECP384R1_KYBER_768_R3_OQS ||
          group == Group_Params::HYBRID_SECP521R1_KYBER_1024_R3_OQS;
}

constexpr bool is_kem(const Group_Params group) {
   return is_pure_kyber(group) || is_hybrid(group);
}

constexpr bool is_post_quantum(const Group_Params group) {
   return is_pure_kyber(group) || is_hybrid(group);
}

std::string group_param_to_string(Group_Params group);
Group_Params group_param_from_string(std::string_view group_name);
std::vector<std::pair<std::string, std::string>> hybrid_group_param_to_algorithm_specs(Group_Params group);
bool group_param_is_dh(Group_Params group);

enum class Kex_Algo {
   STATIC_RSA,
   DH,
   ECDH,
   PSK,
   ECDHE_PSK,
   DHE_PSK,
   KEM,
   KEM_PSK,
   HYBRID,
   HYBRID_PSK,

   // To support TLS 1.3 ciphersuites, which do not determine the kex algo
   UNDEFINED
};

std::string BOTAN_TEST_API kex_method_to_string(Kex_Algo method);
Kex_Algo BOTAN_TEST_API kex_method_from_string(std::string_view str);

inline bool key_exchange_is_psk(Kex_Algo m) {
   return (m == Kex_Algo::PSK || m == Kex_Algo::ECDHE_PSK || m == Kex_Algo::DHE_PSK);
}

}  // namespace Botan::TLS

#endif
