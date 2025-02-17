/*
* TLS Callbacks
* (C) 2016 Matthias Gierlings
*     2016 Jack Lloyd
*     2017 Harry Reimann, Rohde & Schwarz Cybersecurity
*     2022 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CALLBACKS_H_
#define BOTAN_TLS_CALLBACKS_H_

#include <botan/tls_session.h>
#include <botan/tls_alert.h>
#include <botan/pubkey.h>
#include <botan/ocsp.h>
#include <optional>
#include <chrono>

namespace Botan {

class Certificate_Store;
class X509_Certificate;

namespace OCSP {

class Response;

}

namespace TLS {

class Handshake_Message;
class Policy;
class Extensions;
class Certificate_Status_Request;

/**
* Encapsulates the callbacks that a TLS channel will make which are due to
* channel specific operations.
*/
class BOTAN_PUBLIC_API(2,0) Callbacks
   {
   public:
       virtual ~Callbacks() = default;

       /**
       * Mandatory callback: output function
       * The channel will call this with data which needs to be sent to the peer
       * (eg, over a socket or some other form of IPC). The array will be overwritten
       * when the function returns so a copy must be made if the data cannot be
       * sent immediately.
       *
       * @param data the vector of data to send
       *
       * @param size the number of bytes to send
       */
       virtual void tls_emit_data(const uint8_t data[], size_t size) = 0;

       /**
       * Mandatory callback: process application data
       * Called when application data record is received from the peer.
       * Again the array is overwritten immediately after the function returns.
       *
       * @param seq_no the underlying TLS/DTLS record sequence number
       *
       * @param data the vector containing the received record
       *
       * @param size the length of the received record, in bytes
       */
       virtual void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) = 0;

       /**
       * Mandatory callback: alert received
       * Called when an alert is received from the peer
       * If fatal, the connection is closing. If not fatal, the connection may
       * still be closing (depending on the error and the peer).
       *
       * @param alert the source of the alert
       */
       virtual void tls_alert(Alert alert) = 0;

       /**
       * Mandatory callback: session established
       * Called when a session is established. Throw an exception to abort
       * the connection.
       *
       * @param session the session descriptor and its associated handle
       *
       * @return return false to prevent the session from being cached,
       * return true to cache the session in the configured session manager
       */
       virtual bool tls_session_established(const Session_with_Handle& session) = 0;

       /**
       * Optional callback: session activated
       * Called when a session is active and can be written to
       */
       virtual void tls_session_activated() {}

       /**
       * Optional callback: peer closed connection (sent a "close_notify" alert)
       *
       * The peer signaled that it wishes to shut down the connection. The
       * application should not expect to receive any more data from the peer
       * and may tear down the underlying transport socket.
       *
       * Prior to TLS 1.3 it was required that peers discard pending writes
       * and immediately respond with their own "close_notify". With TLS 1.3,
       * applications can continue to send data despite the peer having already
       * signaled their wish to shut down.
       *
       * Returning `true` will cause the TLS 1.3 implementation to write all
       * pending data and then also signal a connection shut down. Otherwise
       * the application is responsible to call the `Channel::close()` method.
       *
       * For TLS 1.2 the return value has no effect.
       *
       * @return true causes the implementation to respond with a "close_notify"
       */
       virtual bool tls_peer_closed_connection()
         {
         return true;
         }

       /**
       * Optional callback: New session ticket received
       * Called when we receive a session ticket from the server at any point
       * after the initial handshake has finished. Clients may decide to keep or
       * discard the session ticket in the configured session manager.
       *
       * Note: this is called for connections that negotiated TLS 1.3 only.
       *
       * @param session the session descriptor
       *
       * @return false to prevent the session from being cached, and true to
       *         cache the session in the configured session manager
       */
       virtual bool tls_session_ticket_received(const Session& session);

       /**
       * Optional callback with default impl: verify cert chain
       *
       * Default implementation performs a standard PKIX validation
       * and initiates network OCSP request for end-entity cert.
       * Override to provide different behavior.
       *
       * Check the certificate chain is valid up to a trusted root, and
       * optionally (if hostname != "") that the hostname given is
       * consistent with the leaf certificate.
       *
       * This function should throw an exception derived from
       * std::exception with an informative what() result if the
       * certificate chain cannot be verified.
       *
       * @param cert_chain specifies a certificate chain leading to a
       *        trusted root CA certificate.
       * @param ocsp_responses the server may have provided some
       * @param trusted_roots the list of trusted certificates
       * @param usage what this cert chain is being used for
       *        Usage_Type::TLS_SERVER_AUTH for server chains,
       *        Usage_Type::TLS_CLIENT_AUTH for client chains,
       *        Usage_Type::UNSPECIFIED for other uses
       * @param hostname when authenticating a server, this is the hostname
       *        the client requested (eg via SNI). When authenticating a client,
       *        this is the server name the client is authenticating *to*.
       *        Empty in other cases or if no hostname was used.
       * @param policy the TLS policy associated with the session being authenticated
       *        using the certificate chain
       */
       virtual void tls_verify_cert_chain(
          const std::vector<X509_Certificate>& cert_chain,
          const std::vector<std::optional<OCSP::Response>>& ocsp_responses,
          const std::vector<Certificate_Store*>& trusted_roots,
          Usage_Type usage,
          const std::string& hostname,
          const TLS::Policy& policy);

       /**
       * Called by default `tls_verify_cert_chain` to get the timeout to use for OCSP
       * requests. Return 0 to disable online OCSP checks.
       *
       * This function should not be "const" since the implementation might need
       * to perform some side effecting operation to compute the result.
       */
       virtual std::chrono::milliseconds tls_verify_cert_chain_ocsp_timeout() const
          {
          return std::chrono::milliseconds(0);
          }

      /**
       * Called by the TLS server whenever the client included the
       * status_request extension (see RFC 6066, a.k.a OCSP stapling)
       * in the ClientHello.
       *
       * @return the encoded OCSP response to be sent to the client which
       * indicates the revocation status of the server certificate. Return an
       * empty vector to indicate that no response is available, and thus
       * suppress the Certificate_Status message.
       */
       virtual std::vector<uint8_t> tls_provide_cert_status(const std::vector<X509_Certificate>& chain,
                                                            const Certificate_Status_Request& csr)
          {
          BOTAN_UNUSED(chain);
          BOTAN_UNUSED(csr);
          return std::vector<uint8_t>();
          }

      /**
       * Called by TLS 1.3 client or server whenever the peer indicated that
       * OCSP stapling is supported. In contrast to `tls_provide_cert_status`,
       * this allows providing OCSP responses for each certificate in the chain.
       *
       * The default implementation invokes `tls_provide_cert_status` assuming
       * that no OCSP responses for intermediate certificates are available.
       *
       * @return a vector of OCSP response buffers. An empty buffer indicates
       *         that no OCSP response should be provided for the respective
       *         certificate (at the same list index). The returned vector
       *         MUST be exactly the same length as the incoming \p chain.
       */
      virtual std::vector<std::vector<uint8_t>> tls_provide_cert_chain_status(const std::vector<X509_Certificate>& chain,
                                                                              const Certificate_Status_Request& csr);

       /**
       * Optional callback with default impl: sign a message
       *
       * Default implementation uses PK_Signer::sign_message().
       * Override to provide a different approach, e.g. using an external device.
       *
       * @param key the private key of the signer
       * @param rng a random number generator
       * @param emsa the encoding method to be applied to the message
       * @param format the signature format
       * @param msg the input data for the signature
       *
       * @return the signature
       */
       virtual std::vector<uint8_t> tls_sign_message(
          const Private_Key& key,
          RandomNumberGenerator& rng,
          const std::string& emsa,
          Signature_Format format,
          const std::vector<uint8_t>& msg);

       /**
       * Optional callback with default impl: verify a message signature
       *
       * Default implementation uses PK_Verifier::verify_message().
       * Override to provide a different approach, e.g. using an external device.
       *
       * @param key the public key of the signer
       * @param emsa the encoding method to be applied to the message
       * @param format the signature format
       * @param msg the input data for the signature
       * @param sig the signature to be checked
       *
       * @return true if the signature is valid, false otherwise
       */
       virtual bool tls_verify_message(
          const Public_Key& key,
          const std::string& emsa,
          Signature_Format format,
          const std::vector<uint8_t>& msg,
          const std::vector<uint8_t>& sig);

       /**
       * Optional callback with default impl: client side DH agreement
       *
       * Default implementation uses PK_Key_Agreement::derive_key().
       * Override to provide a different approach, e.g. using an external device.
       *
       * @param modulus the modulus p of the discrete logarithm group
       * @param generator the generator of the DH subgroup
       * @param peer_public_value the public value of the peer
       * @param policy the TLS policy associated with the session being established
       * @param rng a random number generator
       *
       * @return a pair consisting of the agreed raw secret and our public value
       *
       * TODO: Currently, this is called in TLS 1.2 only. The key agreement mechanics
       *       changed in TLS 1.3, so this callback would (at least) need to be aware
       *       of the negotiated protocol version.
       *       Suggestion: Lets think about a more generic interface for this and
       *                   deprecate/remove this callback in Botan 3.0
       */
       virtual std::pair<secure_vector<uint8_t>, std::vector<uint8_t>> tls_dh_agree(
          const std::vector<uint8_t>& modulus,
          const std::vector<uint8_t>& generator,
          const std::vector<uint8_t>& peer_public_value,
          const Policy& policy,
          RandomNumberGenerator& rng);

       /**
       * Optional callback with default impl: client side ECDH agreement
       *
       * Default implementation uses PK_Key_Agreement::derive_key().
       * Override to provide a different approach, e.g. using an external device.
       *
       * @param curve_name the name of the elliptic curve
       * @param peer_public_value the public value of the peer
       * @param policy the TLS policy associated with the session being established
       * @param rng a random number generator
       * @param compressed the compression preference for our public value
       *
       * @return a pair consisting of the agreed raw secret and our public value
       *
       * TODO: Currently, this is called in TLS 1.2 only. The key agreement mechanics
       *       changed in TLS 1.3, so this callback would (at least) need to be aware
       *       of the negotiated protocol version.
       *       Suggestion: Lets think about a more generic interface for this and
       *                   deprecate/remove this callback in Botan 3.0
       */
       virtual std::pair<secure_vector<uint8_t>, std::vector<uint8_t>> tls_ecdh_agree(
          const std::string& curve_name,
          const std::vector<uint8_t>& peer_public_value,
          const Policy& policy,
          RandomNumberGenerator& rng,
          bool compressed);

       /**
       * Optional callback: inspect handshake message
       * Throw an exception to abort the handshake.
       * Default simply ignores the message.
       *
       * Note: On connections that negotiated TLS 1.3 this callback is also
       *       invoked for post-handshake messages.
       *
       * @param message the handshake message
       */
       virtual void tls_inspect_handshake_msg(const Handshake_Message& message);

       /**
       * Optional callback for server: choose ALPN protocol
       *
       * ALPN (RFC 7301) works by the client sending a list of application
       * protocols it is willing to negotiate. The server then selects which
       * protocol to use. RFC 7301 requires that if the server does not support
       * any protocols offered by the client, then it should close the connection
       * with an alert of no_application_protocol. Within this callback this would
       * be done by throwing a TLS_Exception(Alert::NoApplicationProtocol)
       *
       * @param client_protos the vector of protocols the client is willing to negotiate
       *
       * @return the protocol selected by the server; if the empty string is
       * returned, the server does not reply to the client ALPN extension.
       *
       * The default implementation returns the empty string, causing client
       * ALPN to be ignored.
       *
       * It is highly recommended to support ALPN whenever possible to avoid
       * cross-protocol attacks.
       */
       virtual std::string tls_server_choose_app_protocol(const std::vector<std::string>& client_protos);

      /**
       * Optional callback: examine/modify Extensions before sending.
       *
       * Both client and server will call this callback on the Extensions object
       * before serializing it in the specific handshake message. This allows an
       * application to modify which extensions are sent during the handshake.
       *
       * Default implementation does nothing.
       *
       * @param extn the extensions
       * @param which_side will be Connection_Side::Client or Connection_Side::Server which is the current
       *                   applications role in the exchange.
       * @param which_message will state the handshake message type containing the extensions
       */
       virtual void tls_modify_extensions(Extensions& extn, Connection_Side which_side, Handshake_Type which_message);

       /**
       * Optional callback: examine peer extensions.
       *
       * Both client and server will call this callback with the Extensions
       * object after receiving it from the peer. This allows examining the
       * Extensions, for example to implement a custom extension. It also allows
       * an application to require that a particular extension be implemented;
       * throw an exception from this function to abort the handshake.
       *
       * Default implementation does nothing.
       *
       * @param extn the extensions
       * @param which_side will be Connection_Side::Client if these are are the clients extensions (ie we are
       *        the server) or Connection_Side::Server if these are the server extensions (we are the client).
       * @param which_message will state the handshake message type containing the extensions
       */
       virtual void tls_examine_extensions(const Extensions& extn, Connection_Side which_side, Handshake_Type which_message);

       /**
       * Optional callback: decode TLS group ID
       *
       * TLS uses a 16-bit field to identify ECC and DH groups. This callback
       * handles the decoding. You only need to implement this if you are using
       * a custom ECC or DH group (this is extremely uncommon).
       *
       * Default implementation uses the standard (IETF-defined) mappings.
       *
       * TODO: reconsider this callback together with `tls_dh_agree` and `tls_ecdh_agree`.
       */
       virtual std::string tls_decode_group_param(Group_Params group_param);

      /**
       * Optional callback: parse a single OCSP Response
       *
       * Note: Typically a user of the library would not want to override this
       *       callback. We provide this callback to be able to support OCSP
       *       related tests from BoringSSL's BoGo tests that provide unparsable
       *       responses.
       *
       * Default implementation tries to parse the provided raw OCSP response.
       *
       * This function should not throw an exception but return a std::nullopt
       * if the OCSP response cannot be parsed.
       *
       * @param raw_response raw OCSP response buffer
       * @returns the parsed OCSP response or std::nullopt on error
       */
       virtual std::optional<OCSP::Response> tls_parse_ocsp_response(const std::vector<uint8_t>& raw_response);

       /**
       * Optional callback: return peer network identity
       *
       * There is no expected or specified format. The only expectation is this
       * function will return a unique value. For example returning the peer
       * host IP and port.
       *
       * This is used to bind the DTLS cookie to a particular network identity.
       * It is only called if the dtls-cookie-secret PSK is also defined.
       */
       virtual std::string tls_peer_network_identity();

       /**
       * Optional callback: return a custom time stamp value
       *
       * This allows the library user to specify a custom "now" timestamp when
       * needed. By default it will use the current system clock time.
       *
       * Note that typical usages will not need to override this callback but it
       * is useful for testing purposes to allow for deterministic test outcomes.
       */
       virtual std::chrono::system_clock::time_point tls_current_timestamp();

       /**
       * Optional callback: error logging. (not currently called)
       * @param err An error message related to this connection.
       */
       virtual void tls_log_error(const char* err)
          {
          BOTAN_UNUSED(err);
          }

       /**
       * Optional callback: debug logging. (not currently called)
       * @param what Some hopefully informative string
       */
       virtual void tls_log_debug(const char* what)
          {
          BOTAN_UNUSED(what);
          }

       /**
       * Optional callback: debug logging taking a buffer. (not currently called)
       * @param descr What this buffer is
       * @param val the bytes
       * @param val_len length of val
       */
       virtual void tls_log_debug_bin(const char* descr, const uint8_t val[], size_t val_len)
          {
          BOTAN_UNUSED(descr, val, val_len);
          }
   };

}

}

#endif
