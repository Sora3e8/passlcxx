#include "client.hpp"
#include "header_structs.hpp"
#include "tancrypt/dutils.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <zlib.h>

namespace passl
{
  client::client()
  {
    // Socket initialization
    sock = socket(AF_INET, SOCK_STREAM, 0);
  }

  void client::connect(const char* address, uint32_t port)
  {
    conn_addr = new sockaddr_in();
    conn_addr->sin_family = AF_INET;
    conn_addr->sin_port = htons(port);
    conn_addr->sin_addr.s_addr = inet_addr(address);

    int res = ::connect(sock, (const sockaddr*)conn_addr, sizeof(*conn_addr));
    if (res < 0)
    {
      std::cout << "[passl::client] Could not connect Error:" << errno << ", " << strerror(errno) << std::endl;
      return;
    }

    passl::protocol_header header;
    header.p_chunk.type = 1;
    header.p_chunk.crc = crc32(0L, Z_NULL, 0);
    header.p_chunk.crc = crc32(header.p_chunk.crc, (unsigned char*)(&header.p_chunk.signature), sizeof(protocol_chunk::signature));
    header.p_chunk.crc = crc32(header.p_chunk.crc, (unsigned char*)(&header.p_chunk.type), sizeof(protocol_chunk::type));

    unsigned char* header_serialized = header.get_serialized();
    send(sock, header_serialized, sizeof_protocol_chunk(), 0);
    delete[] header_serialized;
  }

  client::~client()
  {
    close(sock);
    delete conn_addr;
  }
}
