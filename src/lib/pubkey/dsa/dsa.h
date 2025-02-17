/*
* DSA
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DSA_H_
#define BOTAN_DSA_H_

#include <botan/dl_algo.h>

namespace Botan {

/**
* DSA Public Key
*/
class BOTAN_PUBLIC_API(2,0) DSA_PublicKey : public virtual DL_Scheme_PublicKey
   {
   public:
      std::string algo_name() const override { return "DSA"; }

      DL_Group_Format group_format() const override { return DL_Group_Format::ANSI_X9_57; }
      size_t message_parts() const override { return 2; }
      size_t message_part_size() const override { return group_q().bytes(); }

      bool supports_operation(PublicKeyOperation op) const override
         {
         return (op == PublicKeyOperation::Signature);
         }

      /**
      * Load a public key.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits DER encoded public key bits
      */
      DSA_PublicKey(const AlgorithmIdentifier& alg_id,
                    const std::vector<uint8_t>& key_bits);

      /**
      * Create a public key.
      * @param group the underlying DL group
      * @param y the public value y = g^x mod p
      */
      DSA_PublicKey(const DL_Group& group, const BigInt& y);

      std::unique_ptr<PK_Ops::Verification>
         create_verification_op(const std::string& params,
                                const std::string& provider) const override;

      std::unique_ptr<PK_Ops::Verification>
         create_x509_verification_op(const AlgorithmIdentifier& signature_algorithm,
                                     const std::string& provider) const override;
   protected:
      DSA_PublicKey() = default;
   };

/**
* DSA Private Key
*/
class BOTAN_PUBLIC_API(2,0) DSA_PrivateKey final : public DSA_PublicKey,
                                 public virtual DL_Scheme_PrivateKey
   {
   public:
      /**
      * Load a private key.
      * @param alg_id the X.509 algorithm identifier
      * @param key_bits DER encoded key bits in ANSI X9.57 format
      */
      DSA_PrivateKey(const AlgorithmIdentifier& alg_id,
                     const secure_vector<uint8_t>& key_bits);

      /**
      * Create a private key.
      * @param rng the RNG to use
      * @param group the underlying DL group
      * @param private_key the private key (if zero, a new random key is generated)
      */
      DSA_PrivateKey(RandomNumberGenerator& rng,
                     const DL_Group& group,
                     const BigInt& private_key = BigInt::zero());

      std::unique_ptr<Public_Key> public_key() const override;

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      std::unique_ptr<PK_Ops::Signature>
         create_signature_op(RandomNumberGenerator& rng,
                             const std::string& params,
                             const std::string& provider) const override;
   };

}

#endif
