/**
 * HSS - Hierarchical Signatures System (RFC 8554)
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, Philippe Lieser - Rohde & Schwarz Cybersecurity GmbH
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/hss_lms_utils.h>
#include <botan/internal/stl_util.h>

namespace Botan {
PseudorandomKeyGeneration::PseudorandomKeyGeneration(std::span<const uint8_t> identifier) {
   m_input_buffer.resize(identifier.size() + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t));
   BufferStuffer input_stuffer(m_input_buffer);
   input_stuffer.append(identifier);

   m_q = input_stuffer.next(sizeof(uint32_t));
   m_i = input_stuffer.next(sizeof(uint16_t));
   m_j = input_stuffer.next(sizeof(uint8_t)).data();
   BOTAN_ASSERT_NOMSG(input_stuffer.full());
}

void PseudorandomKeyGeneration::gen(std::span<uint8_t> out, HashFunction& hash, std::span<const uint8_t> seed) const {
   hash.update(m_input_buffer);
   hash.update(seed);
   hash.final(out);
}

}  // namespace Botan