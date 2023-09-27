/**
* HSS-LMS
* (C) 2023 Jack Lloyd
*     2023 Fabian Albert, René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hss_lms.h>
#include <botan/rng.h>

#include <botan/internal/hss.h>
#include <botan/internal/pk_ops_impl.h>

namespace Botan {

HSS_LMS_PublicKey::HSS_LMS_PublicKey(std::span<const uint8_t> pub_key) :
      m_public(HSS_LMS_PublicKeyInternal::from_bytes_or_throw(pub_key)) {}

HSS_LMS_PublicKey::~HSS_LMS_PublicKey() = default;

size_t HSS_LMS_PublicKey::key_length() const {
   return m_public->size();
}

size_t HSS_LMS_PublicKey::estimated_strength() const {
   // draft-fluhrer-lms-more-parm-sets-11 Section 9.
   //   As shown in [Katz16], if we assume that the hash function can be
   //   modeled as a random oracle, then the security of the system is at
   //   least 8N-1 bits (where N is the size of the hash output in bytes);
   return 8 * m_public->lms_pub_key().lms_params().m() - 1;
}

std::string HSS_LMS_PublicKey::algo_name() const {
   return m_public->algo_name();
}

AlgorithmIdentifier HSS_LMS_PublicKey::algorithm_identifier() const {
   return m_public->algorithm_identifier();
}

OID HSS_LMS_PublicKey::object_identifier() const {
   return m_public->object_identifier();
}

bool HSS_LMS_PublicKey::check_key(RandomNumberGenerator&, bool) const {
   // Nothing to check. Only useful checks are already done during parsing.
   return true;
}

std::vector<uint8_t> HSS_LMS_PublicKey::public_key_bits() const {
   return m_public->to_bytes();
}

class HSS_LMS_Verification_Operation final : public PK_Ops::Verification {
   public:
      HSS_LMS_Verification_Operation(std::shared_ptr<HSS_LMS_PublicKeyInternal> pub_key) :
            m_public(std::move(pub_key)) {}

      void update(const uint8_t msg[], size_t msg_len) override {
         m_msg_buffer.insert(m_msg_buffer.end(), msg, msg + msg_len);
      }

      bool is_valid_signature(const uint8_t* sig, size_t sig_len) override {
         std::vector<uint8_t> message_to_verify = std::move(m_msg_buffer);
         m_msg_buffer = std::vector<uint8_t>();
         try {
            const auto signature = HSS_Signature::from_bytes_or_throw({sig, sig_len});
            bool sig_valid = m_public->verify_signature(message_to_verify, signature);
            return sig_valid;
         } catch(const Decoding_Error& e) {
            // Signature could not be decoded
            return false;
         }
      }

      std::string hash_function() const override { return m_public->lms_pub_key().lms_params().hash_name(); }

   private:
      std::shared_ptr<HSS_LMS_PublicKeyInternal> m_public;
      std::vector<uint8_t> m_msg_buffer;
};

std::unique_ptr<PK_Ops::Verification> HSS_LMS_PublicKey::create_verification_op(std::string_view /*params*/,
                                                                                std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      return std::make_unique<HSS_LMS_Verification_Operation>(m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> HSS_LMS_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& signature_algorithm, std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      if(signature_algorithm != this->algorithm_identifier()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for HSS-LMS signature");
      }
      return std::make_unique<HSS_LMS_Verification_Operation>(m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

bool HSS_LMS_PublicKey::supports_operation(PublicKeyOperation op) const {
   return op == PublicKeyOperation::Signature;
}

HSS_LMS_PrivateKey::HSS_LMS_PrivateKey(std::span<const uint8_t> private_key) {
   m_private = HSS_LMS_PrivateKeyInternal::from_bytes_or_throw(private_key);
   m_public = std::make_shared<HSS_LMS_PublicKeyInternal>(HSS_LMS_PublicKeyInternal::create(*m_private));
}

HSS_LMS_PrivateKey::HSS_LMS_PrivateKey(RandomNumberGenerator& rng, std::string_view algo_params) {
   HSS_LMS_Params hss_params(algo_params);
   m_private = std::make_shared<HSS_LMS_PrivateKeyInternal>(hss_params, rng);
   m_public = std::make_shared<HSS_LMS_PublicKeyInternal>(HSS_LMS_PublicKeyInternal::create(*m_private));
}

HSS_LMS_PrivateKey::~HSS_LMS_PrivateKey() = default;

secure_vector<uint8_t> HSS_LMS_PrivateKey::private_key_bits() const {
   // TODO: Do we want to private some Botan scoped pkcs8_algorithm_identifier(), instead of re-using the public one?
   // As the private key format is not specified, this would make sure we recognise our own encoding.
   return m_private->to_bytes();
}

secure_vector<uint8_t> HSS_LMS_PrivateKey::raw_private_key_bits() const {
   return private_key_bits();
}

std::unique_ptr<Public_Key> HSS_LMS_PrivateKey::public_key() const {
   return std::make_unique<HSS_LMS_PublicKey>(*this);
}

class HSS_LMS_Signature_Operation final : public PK_Ops::Signature {
   public:
      HSS_LMS_Signature_Operation(std::shared_ptr<HSS_LMS_PrivateKeyInternal> private_key,
                                  std::shared_ptr<HSS_LMS_PublicKeyInternal> public_key) :
            m_private(std::move(private_key)), m_public(std::move(public_key)) {}

      void update(const uint8_t msg[], size_t msg_len) override {
         m_msg_buffer.insert(m_msg_buffer.end(), msg, msg + msg_len);
      }

      secure_vector<uint8_t> sign(RandomNumberGenerator&) override { return m_private->sign(m_msg_buffer); }

      size_t signature_length() const override { return HSS_Signature::size(m_private->hss_params()); }

      AlgorithmIdentifier algorithm_identifier() const override { return m_public->algorithm_identifier(); }

      std::string hash_function() const override { return m_public->lms_pub_key().lms_params().hash_name(); }

   private:
      std::shared_ptr<HSS_LMS_PrivateKeyInternal> m_private;
      std::shared_ptr<HSS_LMS_PublicKeyInternal> m_public;
      std::vector<uint8_t> m_msg_buffer;
};

std::unique_ptr<PK_Ops::Signature> HSS_LMS_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                                                           std::string_view params,
                                                                           std::string_view provider) const {
   BOTAN_UNUSED(rng);
   BOTAN_ARG_CHECK(params.empty(), "Unexpected parameters for signing with HSS-LMS");

   if(provider.empty() || provider == "base") {
      return std::make_unique<HSS_LMS_Signature_Operation>(m_private, m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
