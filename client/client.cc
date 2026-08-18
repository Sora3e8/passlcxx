#include "client.hpp"
#include "header_structs.hpp"
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

    passl::protocol_header header = create_protocol_header();
    header.type = 1;
    header.crc = crc32(0L, Z_NULL, 0);
    header.crc = crc32(header.crc, (unsigned char*)(&header.id), sizeof(protocol_signature));
    header.crc = crc32(header.crc, (unsigned char*)(&header.type), sizeof(passl::protocol_header::type));

    unsigned char* header_serialized = passl::serialize_protocol_header(&header);
    send(sock, header_serialized, sizeof(passl::protocol_header), 0);
    delete[] header_serialized;
  }

  client::~client()
  {
    close(sock);
    delete conn_addr;
  }
}
