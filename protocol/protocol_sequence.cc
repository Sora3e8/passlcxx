#include "protocol_sequence.hpp"
#include "protocol_data.hpp"
#include "tancrypt/aes.hpp"
#include "tancrypt/dutils.hpp"
#include "tancrypt/rsa.hpp"
#include <cstdint>
#include <cstring>
#include <iostream>
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
      protocol_header header(protocol_exchtype::handshake_pubkey, client_pubkey.size(), client_pubkey.size());
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
      if (descriptor.type != protocol_exchtype::handshake_pubkey)
      {
        descriptor.status = protocol_status::state_mismatch;
        return false;
      }

      // Rec size flush
      rec_size = 0;

      // We must read size of the payload + uint32_t (to account for crc32)
      dutils::dbuffer key_data(descriptor.payload_size + sizeof(uint32_t));
      rec_size = recv(sock, key_data.data(), key_data.size(), MSG_WAITALL);

      if (!(rec_size > 0))
      {
        descriptor.status = protocol_status::invalid_data_descriptor;
        return false;
      }

      if (verify_block(key_data.data(), descriptor.block_size))
      {
        key_buffer.loadPubDER(key_data.data() + sizeof(uint32_t), descriptor.block_size);
      }
      else
      {
        return false;
      }

      return true;
    }

    bool retrieve_sharedfrag(int sock, tancrypt::AES::keyc* ssecret_buffer, exchange_role role, protocol_descriptor& descriptor)
    {
      using namespace tancrypt;
      size_t frag_size = AES::RefKeylen(AES::Type::CBC256) / 2;
      if (ssecret_buffer->getKey().size() == 0) ssecret_buffer->_key.resize0(frag_size * 2);
      unsigned char p_header[protocol_header::sizeof_protocol_header()];
      int rec_size = 0;

      // Size with -1 error guard
      rec_size = recv(sock, &p_header, sizeof(p_header), 0);
      if (!(rec_size > 0)) return false;

      if (!protocol_header::read_descriptor(p_header, rec_size, &descriptor)) return false;
      if (descriptor.type != protocol_exchtype::handshake_sharedfrag)
      {
        descriptor.status = protocol_status::state_mismatch;
        return false;
      }
      if (descriptor.payload_size > frag_size + 4)
      {
        descriptor.status = protocol_status::invalid_data_descriptor;
        return false;
      }

      // Rec size flush
      rec_size = 0;

      // We must read size of the payload + uint32_t (to account for crc32)
      dutils::dbuffer frag_data(descriptor.payload_size + sizeof(uint32_t));
      rec_size = recv(sock, frag_data.data(), frag_data.size(), MSG_WAITALL);

      if (!(rec_size > 0))
      {
        descriptor.status = protocol_status::invalid_data_descriptor;
        return false;
      }

      if (verify_block(frag_data.data(), descriptor.block_size))
      {
        memcpy((unsigned char*)ssecret_buffer->getKey().data(), frag_data.data() + sizeof(uint32_t), descriptor.block_size);
      }
      else
      {
        return false;
      }

      return true;
    }

    void sharedfraggen_and_send(int sock, tancrypt::AES::keyc* ssecret_buffer, exchange_role role)
    {
      using namespace tancrypt;

      unsigned int memoffset = 0;
      size_t frag_size = AES::RefKeylen(AES::Type::CBC256) / 2;
      if (ssecret_buffer->getKey().size() == 0) ssecret_buffer->_key.resize0(frag_size * 2);
      AES::keyc shared_fragment = AES::keyc::randomKey(frag_size, AES::Type::CBC256);
      std::cout << "Fragment size: " << shared_fragment.getKey().size() << std::endl;
      // Offsets the shared secret depending on the role in the protocol, client's half goes always first!
      if (role == exchange_role::server) memoffset += frag_size;
      // Writes half of the shared secret into session buffer
      memcpy((char*)(ssecret_buffer->getKey().data() + memoffset), (char*)shared_fragment.getKey().data(), shared_fragment.getKey().size());

      protocol_header header(protocol_exchtype::handshake_sharedfrag, shared_fragment.getKey().size(), shared_fragment.getKey().size());
      unsigned char header_serialized[protocol_header::sizeof_protocol_header()];
      header.serialize(header_serialized);
      uint32_t crc32 = crc_block(shared_fragment.getKey().data(), shared_fragment.getKey().size());

      send(sock, header_serialized, protocol_header::sizeof_protocol_header(), 0);
      send(sock, (unsigned char*)(&crc32), sizeof(uint32_t), 0);
      send(sock, shared_fragment.getKey().data(), shared_fragment.getKey().size(), 0);
    }

  }
}
