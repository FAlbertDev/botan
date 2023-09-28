/**
 * LM-OTS - Leighton-Micali One-Time Signatures
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/lm_ots.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/strong_type.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/hss_lms_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/safeint.h>
#include <botan/internal/stl_util.h>

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

namespace Botan {

namespace {
constexpr uint16_t D_PBLC = 0x8080;
constexpr uint16_t D_MESG = 0x8181;
/// For derivation of C as in https://github.com/cisco/hash-sigs
constexpr uint16_t C_INDEX = 0xFFFD;

class Chain_Generator {
   public:
      Chain_Generator(const LMS_Identifier& identifier, LMS_Tree_Node_Idx q) : m_gen(identifier) {
         m_gen.set_q(q.get());
      }

      void process(HashFunction& hash,
                   uint16_t chain_idx,
                   uint8_t start,
                   uint8_t end,
                   std::span<const uint8_t> in,
                   std::span<uint8_t> out) {
         BOTAN_ARG_CHECK(start <= end, "Start value is bigger than end value");

         if(start == end) {
            copy_into(out, in);
            return;
         }
         m_gen.set_i(chain_idx);

         // Unroll first iteration of the loop
         m_gen.set_j(start++);
         m_gen.gen(out, hash, in);

         for(uint8_t j = start; j < end; ++j) {
            m_gen.set_j(j);
            m_gen.gen(out, hash, out);
         }
      }

   private:
      PseudorandomKeyGeneration m_gen;
};

// RFC 8554 3.1.1
uint8_t byte(std::span<const uint8_t> S, uint32_t i) {
   BOTAN_ARG_CHECK(i < S.size(), "Index out of range");
   return S[i];
}

// RFC 8554 3.1.3
uint8_t coef(std::span<const uint8_t> S, uint32_t i, const LMOTS_Params& params) {
   return params.coef_max() &
          (byte(S, (i * params.w()) / 8) >> (8 - (params.w() * (i % (8 / params.w())) + params.w())));
}

// RFC 8554 4.4
uint16_t checksum(const LMOTS_Params& params, std::span<const uint8_t> S) {
   size_t sum = 0;
   for(uint32_t i = 0; i < (params.n() * 8 / params.w()); ++i) {
      sum += params.coef_max() - coef(S, i, params);
   }
   return checked_cast_to<uint16_t>(sum << params.ls());
}

std::vector<uint8_t> gen_Q_with_cksm(const LMOTS_Params& params,
                                     const LMS_Identifier& identifier,
                                     const LMS_Tree_Node_Idx& q,
                                     std::span<const uint8_t> C,
                                     const LMS_Message& msg) {
   std::vector<uint8_t> Q_with_cksm(params.n() + sizeof(uint16_t));
   BufferStuffer qwc_stuffer(Q_with_cksm);
   const auto hash = HashFunction::create_or_throw(params.hash_name());
   hash->update(identifier);
   hash->update_be(q.get());
   hash->update_be(D_MESG);
   hash->update(C);
   hash->update(msg);
   auto Q_span = qwc_stuffer.next(params.n());
   hash->final(Q_span);

   qwc_stuffer.append_be(checksum(params, Q_span));

   return Q_with_cksm;
}

}  // namespace

LMOTS_Params LMOTS_Params::create_or_throw(LMOTS_Algorithm_Type type) {
   uint8_t type_value = static_cast<uint8_t>(type);

   if(type >= LMOTS_Algorithm_Type::SHA256_N32_W1 && type <= LMOTS_Algorithm_Type::SHA256_N32_W8) {
      uint8_t w = 1 << (type_value - static_cast<uint8_t>(LMOTS_Algorithm_Type::SHA256_N32_W1));
      return LMOTS_Params(type, "SHA-256", w);
   }
   if(type >= LMOTS_Algorithm_Type::SHA256_N24_W1 && type <= LMOTS_Algorithm_Type::SHA256_N24_W8) {
      uint8_t w = 1 << (type_value - static_cast<uint8_t>(LMOTS_Algorithm_Type::SHA256_N24_W1));
      return LMOTS_Params(type, "Truncated(SHA-256,192)", w);
   }
   if(type >= LMOTS_Algorithm_Type::SHAKE_N32_W1 && type <= LMOTS_Algorithm_Type::SHAKE_N32_W8) {
      uint8_t w = 1 << (type_value - static_cast<uint8_t>(LMOTS_Algorithm_Type::SHAKE_N32_W1));
      return LMOTS_Params(type, "SHAKE-256(256)", w);
   }
   if(type >= LMOTS_Algorithm_Type::SHAKE_N24_W1 && type <= LMOTS_Algorithm_Type::SHAKE_N24_W8) {
      uint8_t w = 1 << (type_value - static_cast<uint8_t>(LMOTS_Algorithm_Type::SHAKE_N24_W1));
      return LMOTS_Params(type, "SHAKE-256(192)", w);
   }

   throw Decoding_Error("Unsupported LM-OTS algorithm type");
}

LMOTS_Params LMOTS_Params::create_or_throw(std::string_view hash_name, uint8_t w) {
   BOTAN_ARG_CHECK(w == 1 || w == 2 || w == 4 || w == 8, "Invalid w value");
   auto type_offset = high_bit(w) - 1;
   LMOTS_Algorithm_Type base_type;

   if(hash_name == "SHA-256") {
      base_type = LMOTS_Algorithm_Type::SHA256_N32_W1;
   } else if(hash_name == "Truncated(SHA-256,192)") {
      base_type = LMOTS_Algorithm_Type::SHA256_N24_W1;
   } else if(hash_name == "SHAKE-256(256)") {
      base_type = LMOTS_Algorithm_Type::SHAKE_N32_W1;
   } else if(hash_name == "SHAKE-256(192)") {
      base_type = LMOTS_Algorithm_Type::SHAKE_N24_W1;
   } else {
      throw Decoding_Error("Unsupported hash function");
   }
   auto type = static_cast<LMOTS_Algorithm_Type>(static_cast<uint8_t>(base_type) + type_offset);
   return LMOTS_Params(type, hash_name, w);
}

LMOTS_Params::LMOTS_Params(LMOTS_Algorithm_Type algorithm_type, std::string_view hash_name, uint8_t w) :
      m_algorithm_type(algorithm_type), m_w(w), m_hash_name(hash_name) {
   const auto hash = HashFunction::create_or_throw(m_hash_name);
   m_n = hash->output_length();
   // RFC 8553 Appendix B - Parameter Computation
   auto u = ceil_division<size_t>(8 * m_n, m_w);                         // ceil(8*n/w)
   auto v = ceil_division<size_t>(high_bit(((1 << m_w) - 1) * u), m_w);  // ceil((floor(lg[(2^w - 1) * u]) + 1) / w)
   m_ls = 16 - (v * w);
   m_p = u + v;
}

LMOTS_Signature::LMOTS_Signature(LMOTS_Algorithm_Type lmots_type,
                                 std::vector<uint8_t> C,
                                 std::vector<uint8_t> y_buffer) :
      m_algorithm_type(lmots_type), m_C(std::move(C)), m_y_buffer(std::move(y_buffer)) {
   LMOTS_Params params = LMOTS_Params::create_or_throw(m_algorithm_type);

   BufferSlicer y_slicer(m_y_buffer);
   for(uint16_t i = 0; i < params.p(); ++i) {
      m_y.push_back(y_slicer.take<LMOTS_Node>(params.n()));
   }
}

LMOTS_Signature LMOTS_Signature::from_bytes_or_throw(BufferSlicer& slicer) {
   size_t total_remaining_bytes = slicer.remaining();
   // Alg. 6a. 1. (last 4 bytes) / Alg. 4b. 1.
   if(total_remaining_bytes < sizeof(LMOTS_Algorithm_Type)) {
      throw Decoding_Error("To few signature bytes while parsing LMOTS signature.");
   }
   // Alg. 6a. 2.b. / Alg. 4b. 2.a.
   auto algorithm_type = slicer.copy_be<LMOTS_Algorithm_Type>();

   // Alg. 6a. 2.d. / Alg. 4b. 2.c.
   LMOTS_Params params = LMOTS_Params::create_or_throw(algorithm_type);

   if(total_remaining_bytes < size(params)) {
      throw Decoding_Error("To few signature bytes while parsing LMOTS signature.");
   }

   // Alg. 4b. 2.d.
   auto C = slicer.copy_as_vector(params.n());
   // Alg. 4b. 2.e.
   auto m_y_buffer = slicer.copy_as_vector(params.p() * params.n());

   return LMOTS_Signature(algorithm_type, std::move(C), std::move(m_y_buffer));
}

LMOTS_Private_Key::LMOTS_Private_Key(const LMOTS_Params& params,
                                     const LMS_Identifier& identifier,
                                     LMS_Tree_Node_Idx q,
                                     const LMS_Seed& seed) :
      OTS_Instance(params, identifier, q), m_seed(seed) {
   PseudorandomKeyGeneration gen(identifier);
   const auto hash = HashFunction::create_or_throw(params.hash_name());

   gen.set_q(q.get());
   gen.set_j(0xff);

   for(uint16_t i = 0; i < params.p(); ++i) {
      gen.set_i(i);
      m_ots_sk.push_back(gen.gen<LMOTS_Node>(*hash, seed));
   }
}

void LMOTS_Private_Key::sign(StrongSpan<LMOTS_Signature_Bytes> out_sig, const LMS_Message& msg) const {
   BOTAN_ARG_CHECK(out_sig.size() == LMOTS_Signature::size(params()), "Invalid output buffer size");
   BufferStuffer sig_stuffer(out_sig);
   const auto hash = HashFunction::create_or_throw(params().hash_name());
   sig_stuffer.append_be(params().algorithm_type());
   const auto C = sig_stuffer.next(params().n());

   // Since we do not store the signatures of the lms trees in the HSS sk,
   // we need deterministic signatures to avoid reusing a OTS key to generate multiple signatures.
   // See also: lm_ots_sign.c 110-119 (of cisco implementation)
   derive_random_C(C, *hash);

   const auto Q_with_cksm = gen_Q_with_cksm(params(), identifier(), q(), C, msg);

   Chain_Generator chain_gen(identifier(), q());
   for(uint16_t i = 0; i < params().p(); ++i) {
      const auto y_i = sig_stuffer.next(params().n());
      const uint8_t a = coef(Q_with_cksm, i, params());
      chain_gen.process(*hash, i, 0, a, chain_input(i), y_i);
   }
   BOTAN_ASSERT_NOMSG(sig_stuffer.full());
}

void LMOTS_Private_Key::derive_random_C(std::span<uint8_t> out, HashFunction& hash) const {
   PseudorandomKeyGeneration gen(identifier());

   gen.set_q(q().get());
   gen.set_i(C_INDEX);
   gen.set_j(0xff);

   gen.gen(out, hash, m_seed);
}

LMOTS_Public_Key::LMOTS_Public_Key(const LMOTS_Private_Key& lmots_sk) : OTS_Instance(lmots_sk) {
   const auto pk_hash = HashFunction::create_or_throw(lmots_sk.params().hash_name());
   pk_hash->update(lmots_sk.identifier());
   pk_hash->update_be(lmots_sk.q().get());
   pk_hash->update_be(D_PBLC);

   Chain_Generator chain_gen(lmots_sk.identifier(), lmots_sk.q());
   const auto hash = HashFunction::create_or_throw(lmots_sk.params().hash_name());
   LMOTS_Node tmp(lmots_sk.params().n());
   for(uint16_t i = 0; i < lmots_sk.params().p(); ++i) {
      chain_gen.process(*hash, i, 0, lmots_sk.params().coef_max(), lmots_sk.chain_input(i), tmp);
      pk_hash->update(tmp);
   }

   m_K = pk_hash->final<LMOTS_K>();
}

LMOTS_K lmots_compute_pubkey_from_sig(const LMOTS_Signature& sig,
                                      const LMS_Message& msg,
                                      const LMS_Identifier& identifier,
                                      LMS_Tree_Node_Idx q) {
   auto params = LMOTS_Params::create_or_throw(sig.algorithm_type());

   // Alg. 4b 3.

   const auto Q_with_cksm = gen_Q_with_cksm(params, identifier, q, sig.C(), msg);

   // Prefill the final hash object
   const auto pk_hash = HashFunction::create_or_throw(params.hash_name());
   pk_hash->update(identifier);
   pk_hash->update_be(q.get());
   pk_hash->update_be(D_PBLC);

   Chain_Generator chain_gen(identifier, q);
   const auto hash = HashFunction::create_or_throw(params.hash_name());
   LMOTS_Node tmp(params.n());
   for(uint16_t i = 0; i < params.p(); ++i) {
      const uint8_t a = coef(Q_with_cksm, i, params);
      chain_gen.process(*hash, i, a, params.coef_max(), sig.y(i), tmp);
      pk_hash->update(tmp);
   }
   // Alg. 4b 4.
   return pk_hash->final<LMOTS_K>();
}

}  // namespace Botan
