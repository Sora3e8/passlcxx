#ifndef PASSL_HEADER_STRUCTS_HPP
#define PASSL_HEADER_STRUCTS_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <uchar.h>
#include <zlib.h>

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

      protocol_header() { }
      protocol_header(uint8_t type, size_t payload_size, size_t block_size)
      {
        p_chunk.type = type;
        p_chunk.crc = crc32(0L, Z_NULL, 0);
        p_chunk.crc = crc32(p_chunk.crc, (unsigned char*)(p_chunk.signature), sizeof(protocol_chunk::signature));
        p_chunk.crc = crc32(p_chunk.crc, (unsigned char*)((&p_chunk.type)), sizeof(protocol_chunk::type));
      }

      const static bool read_descriptor(unsigned char data[sizeof_protocol_header()], size_t size, protocol_descriptor* descriptor)
      {
        if (size != sizeof_protocol_header())
        {
          descriptor->status = protocol_status::truncated_data;
          return false;
        }

        uint32_t crc_received = *(uint32_t*)(data + sizeof_protocol_chunk() - sizeof(protocol_chunk::crc));
        uint32_t crc_local = crc32(0L, Z_NULL, 0);

        crc_local = crc32(crc_local, data, sizeof_protocol_chunk() - sizeof(protocol_chunk::crc));
        if (crc_local != crc_received)
        {
          descriptor->status = protocol_status::bad_crc;
          return false;
        }

        if (memcmp((char*)data, (char*)protocol_chunk::signature, sizeof(protocol_chunk::signature)) != 0)
        {
          descriptor->status = protocol_status::unknown_protocol;
          return false;
        }

        descriptor->type = *(uint8_t*)(data + sizeof(protocol_chunk::signature));
        descriptor->payload_size = *(uint8_t*)(data + sizeof_protocol_chunk() + sizeof(data_chunk::signature));
        descriptor->block_size = *(uint8_t*)(data + sizeof_protocol_chunk() + sizeof(data_chunk::signature));
        return true;
      }

      unsigned char* get_serialized()
      {
        unsigned char* serial_data = new unsigned char[sizeof_protocol_header()];
        unsigned char* buffer_ptr = serial_data;

        // p_chunk serialization
        memcpy(buffer_ptr, p_chunk.signature, sizeof(p_chunk.signature));
        buffer_ptr += sizeof(p_chunk.signature);
        memcpy(buffer_ptr, (unsigned char*)(&p_chunk.type), sizeof(p_chunk.type));
        buffer_ptr += sizeof(p_chunk.type);
        memcpy(buffer_ptr, (unsigned char*)(&p_chunk.crc), sizeof(p_chunk.crc));
        buffer_ptr += sizeof(p_chunk.crc);

        // d_chunk serialization
        memcpy(buffer_ptr, d_chunk.signature, sizeof(d_chunk.signature));
        buffer_ptr += sizeof(d_chunk.signature);
        memcpy(buffer_ptr, (unsigned char*)(&d_chunk.payload_size), sizeof(d_chunk.payload_size));
        buffer_ptr += sizeof(d_chunk.payload_size);
        memcpy(buffer_ptr, (unsigned char*)(&d_chunk.block_size), sizeof(d_chunk.block_size));
        buffer_ptr += sizeof(d_chunk.block_size);
        memcpy(buffer_ptr, (unsigned char*)(&d_chunk.crc), sizeof(d_chunk.crc));
        buffer_ptr += sizeof(d_chunk.crc);

        return serial_data;
      }
  };

}

#endif
