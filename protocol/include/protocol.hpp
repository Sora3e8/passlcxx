#ifndef PASSL_PROTOCOL_HPP
#define PASSL_PROTOCOL_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <uchar.h>

namespace passl
{

  struct protocol_chunk
  {
      constexpr static uint8_t signature[5] = { 0x50, 0x41, 0x53, 0x53, 0x4c };
      uint8_t type;
      uint32_t crc;
  };

  constexpr size_t sizeof_protocol_chunk()
  {
    return sizeof(protocol_chunk::signature) + sizeof(protocol_chunk::type) + sizeof(protocol_chunk::crc);
  }

  struct data_chunk
  {
      constexpr static uint8_t signature[4] = { 0x44, 0x41, 0x54, 0x41 };
      size_t payload_size;
      size_t block_size;
      uint32_t crc;
  };

  constexpr size_t sizeof_data_chunk()
  {
    return sizeof(data_chunk::signature) + sizeof(data_chunk::payload_size) + sizeof(data_chunk::block_size) + sizeof(data_chunk::crc);
  }

  constexpr size_t sizeof_protocol_header()
  {
    return sizeof_protocol_chunk() + sizeof_data_chunk();
  }

  enum protocol_status
  {
    ok = 0,
    unknown_protocol,
    bad_crc,
    state_mismatch,
    truncated_data

  };

  inline const char* prot_errstr(protocol_status status)
  {
    switch (status)
    {
      case protocol_status::ok:
        return "OK";
      case protocol_status::unknown_protocol:
        return "Unknown protocol";
      case protocol_status::bad_crc:
        return "CRC validation failed";
      case protocol_status::state_mismatch:
        return "State mismatch";
      case protocol_status::truncated_data:
        return "Truncated data";
      default:
        return "Unknown error";
    }
  }

  struct protocol_descriptor
  {
      uint8_t type;
      size_t payload_size;
      size_t block_size;
      protocol_status status;
  };

  class protocol_header
  {
    public:
      protocol_chunk p_chunk;
      data_chunk d_chunk;

      protocol_header();
      protocol_header(uint8_t type, size_t payload_size, size_t block_size);

      const static bool read_descriptor(unsigned char data[sizeof_protocol_header()], size_t size, protocol_descriptor* descriptor);

      unsigned char* get_serialized();
  };

}

#endif
