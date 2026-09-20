#ifndef PASSL_PROTOCOL_SEQUENCE_HPP
#define PASSL_PROTOCOL_SEQUENCE_HPP

#include <cstddef>

namespace dutils { class dbuffer; }

namespace tancrypt
{
  namespace RSA { class pkic; }
}

namespace passl
{
  namespace protocol_data { struct protocol_descriptor; }
  namespace protocol_sequence
  {
    using namespace protocol_data;
    void keygen_and_send(int sock, tancrypt::RSA::pkic& key_buffer, size_t keysize);
    bool retrieve_pubkey(int sock, tancrypt::RSA::pkic& key_buffer, protocol_descriptor& descriptor);
  }
}
#endif
