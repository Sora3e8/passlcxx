#include "protocol.hpp"
#include <cerrno>
#include <cstring>
#include <iostream>
#include <zlib.h>

namespace passl
{
  protocol_header::protocol_header() { }
  protocol_header::protocol_header(uint8_t type, size_t payload_size, size_t block_size)
  {
    p_section.type = type;
    p_section.crc = crc32(0L, Z_NULL, 0);
    p_section.crc = crc32(p_section.crc, (unsigned char*)(p_section.signature), sizeof(protocol_section::signature));
    p_section.crc = crc32(p_section.crc, (unsigned char*)((&p_section.type)), sizeof(protocol_section::type));
    d_section.payload_size = payload_size;
    d_section.block_size = block_size;
    d_section.crc = crc32(0L, Z_NULL, 0);
    d_section.crc = crc32(d_section.crc, (unsigned char*)(d_section.signature), sizeof(data_section::signature));
  }
  const bool protocol_header::read_descriptor(unsigned char* data, size_t size, protocol_descriptor* descriptor)
  {
    if (size < sizeof_protocol_header())
    {
      descriptor->status = protocol_status::truncated_data;
      return false;
    }

    uint32_t crc_received = *(uint32_t*)(data + sizeof_protocol_section() - sizeof(protocol_section::crc));
    uint32_t crc_local = crc32(0L, Z_NULL, 0);

    crc_local = crc32(crc_local, data, sizeof_protocol_section() - sizeof(protocol_section::crc));
    if (crc_local != crc_received)
    {
      descriptor->status = protocol_status::bad_crc;
      return false;
    }

    if (memcmp((char*)data, (char*)protocol_section::signature, sizeof(protocol_section::signature)) != 0)
    {
      descriptor->status = protocol_status::unknown_protocol;
      return false;
    }

    descriptor->type = *(uint8_t*)(data + sizeof(protocol_section::signature));
    descriptor->payload_size = *(uint8_t*)(data + sizeof_protocol_section() + sizeof(data_chunk::signature));
    descriptor->block_size = *(uint8_t*)(data + sizeof_protocol_section() + sizeof(data_chunk::signature));
    return true;
  }

  void dblock_iterator::iterate(const std::function<bool(uint32_t crc, unsigned char* data, size_t data_size)> lambda)
  {
    unsigned char* data_ptr = data + pre_offset;
    size_t blocks = data_size / (block_size + pre_offset);
    size_t irr_blocksize = data_size % block_size;

    // Safeguard if size 0
    if (blocks == 0 && irr_blocksize == 0) return;
    for (int i = 0; i < blocks; i++)
    {
      uint32_t block_crc = crc32(0L, Z_NULL, 0);
      block_crc = crc32(block_crc, data_ptr, block_size);
      bool res = lambda(block_crc, data_ptr, block_size);
      if (!res)
      {
        std::cout << "Could not send data, error code " << errno << "\n"
                  << strerror(errno) << std::endl;
        break;
      }
      data_ptr += (block_size + pre_offset + post_offset);
    }
  }

  unsigned char* protocol_header::get_serialized()
  {
    unsigned char* serial_data = new unsigned char[sizeof_protocol_header()];
    unsigned char* buffer_ptr = serial_data;

    // p_section serialization
    memcpy(buffer_ptr, p_section.signature, sizeof(p_section.signature));
    buffer_ptr += sizeof(p_section.signature);
    memcpy(buffer_ptr, (unsigned char*)(&p_section.type), sizeof(p_section.type));
    buffer_ptr += sizeof(p_section.type);
    memcpy(buffer_ptr, (unsigned char*)(&p_section.crc), sizeof(p_section.crc));
    buffer_ptr += sizeof(p_section.crc);

    // d_section serialization
    memcpy(buffer_ptr, d_section.signature, sizeof(d_section.signature));
    buffer_ptr += sizeof(d_section.signature);
    memcpy(buffer_ptr, (unsigned char*)(&d_section.payload_size), sizeof(d_section.payload_size));
    buffer_ptr += sizeof(d_section.payload_size);
    memcpy(buffer_ptr, (unsigned char*)(&d_section.block_size), sizeof(d_section.block_size));
    buffer_ptr += sizeof(d_section.block_size);
    memcpy(buffer_ptr, (unsigned char*)(&d_section.crc), sizeof(d_section.crc));
    buffer_ptr += sizeof(d_section.crc);

    return serial_data;
  }

}
