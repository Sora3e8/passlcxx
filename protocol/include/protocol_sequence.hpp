#ifndef PASSL_PROTOCOL_SEQUENCE_HPP
#define PASSL_PROTOCOL_SEQUENCE_HPP

#include <cstddef>

namespace dutils { class dbuffer; }

namespace tancrypt
{
  namespace AES { class keyc; }
  namespace RSA { class pkic; }
}

namespace passl
{
  namespace protocol_data { struct protocol_descriptor; }
  namespace protocol_sequence
  {
    using namespace protocol_data;

    enum exchange_role
    {
      invalid = 0,
      server,
      client
    };

    void keygen_and_send(int sock, tancrypt::RSA::pkic& key_buffer, size_t keysize);
    void sharedfraggen_and_send(int sock, tancrypt::AES::keyc* ssecret_buffer, exchange_role role);
    bool retrieve_pubkey(int sock, tancrypt::RSA::pkic& key_buffer, protocol_descriptor& descriptor);
  }
}
#endif
