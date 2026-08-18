#ifndef PASSL_HEADER_STRUCTS_HPP
#define PASSL_HEADER_STRUCTS_HPP

#include <cstdint>
#include <cstring>
#include <uchar.h>

namespace passl
{
  const char8_t protocol_signature[5] = { 0x50, 0x41, 0x53, 0x53, 0x4c };

  struct protocol_header
  {
      char8_t id[5] = { };
      uint8_t type;
      uint32_t crc = 0;
  };

  inline protocol_header create_protocol_header()
  {
    protocol_header head = { };
    memcpy(head.id, &protocol_signature, 5);

    return head;
  };

  inline unsigned char* serialize_protocol_header(protocol_header* header)
  {
    unsigned char* serialized = new unsigned char[sizeof(protocol_header)];
    unsigned char* buffer_p = serialized;
    memcpy(buffer_p, header->id, sizeof(protocol_signature));
    buffer_p += sizeof(protocol_signature);
    memcpy(buffer_p, &(header->type), sizeof(protocol_header::type));
    buffer_p += sizeof(header->type);
    memcpy(buffer_p, &(header->crc), sizeof(protocol_header::crc));

    return serialized;
  }

  struct data_header
  {
      char8_t id[4] = { };
      uint32_t size = 0;
      uint32_t crc = 0;
  };

}

#endif
