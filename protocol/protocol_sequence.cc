#include "protocol_sequence.hpp"
#include "protocol_data.hpp"
#include "tancrypt/dutils.hpp"
#include "tancrypt/rsa.hpp"
#include <netinet/in.h>
#include <sys/socket.h>

using namespace passl::protocol_data;

namespace passl
{
  namespace protocol_sequence
  {
    void keygen_and_send(int sock, tancrypt::RSA::pkic& key_buffer, size_t keysize)
    {
      key_buffer.generate_keypair(keysize);
      dutils::dbuffer client_pubkey = key_buffer.getPubDER();

      // Prepare header to carry the pubkey
      protocol_header header(1, client_pubkey.size(), client_pubkey.size());
      unsigned char header_serialized[protocol_header::sizeof_protocol_header()];
      header.serialize(header_serialized);
      uint32_t crc32 = crc_block(client_pubkey.data(), client_pubkey.size());

      send(sock, header_serialized, protocol_header::sizeof_protocol_header(), 0);
      send(sock, (unsigned char*)(&crc32), sizeof(uint32_t), 0);
      send(sock, client_pubkey.data(), client_pubkey.size(), 0);
    }

    bool retrieve_pubkey(int sock, tancrypt::RSA::pkic& key_buffer, protocol_descriptor& descriptor)
    {
      unsigned char p_header[protocol_header::sizeof_protocol_header()];
      int rec_size = 0;

      // Size with -1 error guard
      rec_size = recv(sock, &p_header, sizeof(p_header), 0);
      if (!(rec_size > 0)) return false;

      if (!protocol_header::read_descriptor(p_header, rec_size, &descriptor)) return false;

      // Rec size flush
      rec_size = 0;

      // We must read size of the payload + uint32_t (to account for crc32)
      dutils::dbuffer key_data(descriptor.payload_size + sizeof(uint32_t));
      rec_size = recv(sock, key_data.data(), key_data.size(), 0);

      if (!(rec_size > 0))
      {
        descriptor.status = protocol_status::invalid_data_descriptor;
        return false;
      }

      if (!verify_block(key_data.data(), descriptor.block_size)) key_buffer.loadPubDER(key_data.data() + sizeof(uint32_t), descriptor.payload_size);

      return true;
    }

  }
}
