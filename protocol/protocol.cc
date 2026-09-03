#include "protocol.hpp"
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <zlib.h>

namespace passl
{
  protocol_header::protocol_header() { }
  protocol_header::protocol_header(uint8_t type, size_t payload_size, size_t block_size)
  {
    p_section.type = type;
    d_section.payload_size = payload_size;
    d_section.block_size = block_size;

    p_section.crc = crc32(0L, Z_NULL, 0);
    p_section.crc = crc32(p_section.crc, (unsigned char*)(p_section.signature), sizeof(protocol_section::signature));
    p_section.crc = crc32(p_section.crc, (unsigned char*)((&p_section.type)), sizeof(protocol_section::type));

    d_section.crc = crc32(0L, Z_NULL, 0);
    d_section.crc = crc32(d_section.crc, (unsigned char*)(d_section.signature), sizeof(data_section::signature));
    d_section.crc = crc32(d_section.crc, (unsigned char*)(&d_section.payload_size), sizeof(data_section::payload_size));
    d_section.crc = crc32(d_section.crc, (unsigned char*)(&d_section.block_size), sizeof(data_section::block_size));
  }

  const bool protocol_header::read_descriptor(unsigned char* data, size_t size, protocol_descriptor* descriptor)
  {
    /* size_checks */
    if (size > sizeof_protocol_header()) throw std::overflow_error("[passl::protocol_header::read_descriptor] Critical error, data too big to be valid descriptor.");

    if (size < sizeof_protocol_header())
    {
      descriptor->status = protocol_status::truncated_data;
      return false;
    }
    /* size_checks end*/

    // crc setup
    uint32_t crc_received = 0;
    uint32_t crc_local = crc32(0L, Z_NULL, 0);

    /* p_section verify */
    // Load crc from the section and eval one from the received data
    crc_received = *(uint32_t*)(data + protocol_header::sizeof_protocol_section() - sizeof(protocol_header::protocol_section::crc));
    crc_local = crc32(crc_local, data, protocol_header::sizeof_protocol_section() - sizeof(protocol_header::protocol_section::crc));

    // Check integrity of the section's crc against crc evaluated from the data we received
    if (crc_local != crc_received)
    {
      descriptor->status = protocol_status::bad_crc;
      return false;
    }

    // crc_local flush after use
    crc_local = crc32(0L, Z_NULL, 0);

    // Check validity of the protocol signature
    if (memcmp((char*)data, (char*)protocol_section::signature, sizeof(protocol_section::signature)) != 0)
    {
      descriptor->status = protocol_status::unknown_protocol;
      return false;
    }
    /* p_section verify end*/

    /* p_section write */
    descriptor->type = *(uint8_t*)(data + sizeof(protocol_section::signature));
    /* p_section write end */

    /* d_section_verify */
    crc_received = *(uint32_t*)(data + sizeof_protocol_header() - sizeof(protocol_section::crc));
    crc_local = crc32(crc_local, data + sizeof_protocol_section(), sizeof_data_section() - sizeof(data_section::crc));

    if (crc_local != crc_received)
    {
      descriptor->status = protocol_status::bad_crc;
      return false;
    }

    // Check validity of the data signature
    if (memcmp((char*)data + sizeof_protocol_section(), (char*)data_section::signature, sizeof(data_section::signature)) != 0)
    {
      descriptor->status = protocol_status::unknown_protocol;
      return false;
    }

    /* d_section_verify end */

    descriptor->payload_size = *(uint8_t*)(data + sizeof_protocol_section() + sizeof(data_section::signature));
    descriptor->block_size = *(uint8_t*)(data + sizeof_protocol_section() + sizeof(data_section::signature));
    return true;
  }

  void dblock_iterator::iterate(const std::function<bool(uint32_t crc, unsigned char* data, size_t data_size)> lambda)
  {
    unsigned char* data_ptr = data + pre_offset;
    size_t blocks = data_size / (block_size + pre_offset);
    size_t irr_blocksize = data_size % block_size;

    // Safeguard if size 0
    if (blocks == 0 && irr_blocksize == 0)
      return;

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
    memcpy(buffer_ptr, (unsigned char*)(&p_section.type),
           sizeof(p_section.type));
    buffer_ptr += sizeof(p_section.type);
    memcpy(buffer_ptr, (unsigned char*)(&p_section.crc), sizeof(p_section.crc));
    buffer_ptr += sizeof(p_section.crc);

    // d_section serialization
    memcpy(buffer_ptr, d_section.signature, sizeof(d_section.signature));
    buffer_ptr += sizeof(d_section.signature);
    memcpy(buffer_ptr, (unsigned char*)(&d_section.payload_size),
           sizeof(d_section.payload_size));
    buffer_ptr += sizeof(d_section.payload_size);
    memcpy(buffer_ptr, (unsigned char*)(&d_section.block_size),
           sizeof(d_section.block_size));
    buffer_ptr += sizeof(d_section.block_size);
    memcpy(buffer_ptr, (unsigned char*)(&d_section.crc), sizeof(d_section.crc));
    buffer_ptr += sizeof(d_section.crc);

    return serial_data;
  }

} // namespace passl
