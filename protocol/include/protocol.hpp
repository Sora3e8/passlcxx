#ifndef PASSL_PROTOCOL_HPP
#define PASSL_PROTOCOL_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <uchar.h>

namespace passl
{
  enum protocol_status
  {
    ok = 0,
    unknown_protocol,
    invalid_data_descriptor,
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
      case protocol_status::invalid_data_descriptor:
        return "U";
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

  uint32_t crc_block(unsigned char* data, size_t block_size);
  bool verify_block(unsigned char* data, size_t block_size);
  class chunk_iterator
  {
    public:
      size_t data_size = 0;
      size_t chunk_size = 0;
      size_t pre_offset = 0;
      size_t post_offset = 0;
      size_t ptr_pos = 0;
      size_t chunk_count = 0;

      chunk_iterator(unsigned char* data, size_t data_size, size_t chunk_size)
      {
        this->data = data;
        this->data_size = data_size;
        this->chunk_size = chunk_size;
        this->chunk_count = data_size / chunk_size;
      }
      void iterate(const std::function<bool(unsigned char* data, size_t data_size)> lambda);
      unsigned char* data = nullptr;
  };

  class protocol_header
  {
    public:
      struct protocol_section
      {
          constexpr static uint8_t signature[5] = { 0x50, 0x41, 0x53, 0x53, 0x4c };
          uint8_t type;
          uint32_t crc;
      } p_section;
      struct data_section
      {
          constexpr static uint8_t signature[4] = { 0x44, 0x41, 0x54, 0x41 };
          size_t payload_size;
          size_t block_size;
          uint32_t crc;
      } d_section;

      protocol_header();
      protocol_header(uint8_t type, size_t payload_size, size_t block_size);

      static constexpr size_t sizeof_protocol_section()
      {
        return sizeof(protocol_section::signature) + sizeof(protocol_section::type) + sizeof(protocol_section::crc);
      }

      static constexpr size_t sizeof_data_section()
      {
        return sizeof(data_section::signature) + sizeof(data_section::payload_size) + sizeof(data_section::block_size) + sizeof(data_section::crc);
      }

      static constexpr size_t sizeof_protocol_header()
      {
        return sizeof_protocol_section() + sizeof_data_section();
      }

      const static bool read_descriptor(unsigned char* data, size_t size, protocol_descriptor* descriptor);
      unsigned char* get_serialized();
  };

}

#endif
