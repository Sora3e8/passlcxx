#include "client.hpp"
#include "passl/protocol.hpp"
#include "protocol.hpp"
#include "tancrypt/rsa.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>

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
      std::cout << "[passl::client] Could not connect Error:" << errno << ", "
                << strerror(errno) << std::endl;
      return;
    }

    // Initialize keypair and extract pubkey
    tancrypt::RSA::pkic client_key;
    client_key.generate_keypair(key_bitsize);
    dutils::dbuffer client_pubkey = client_key.getPubDER();

    // Prepare header to carry the pubkey
    passl::protocol_header header(1, client_pubkey.size(), client_pubkey.size());
    unsigned char* header_serialized = header.get_serialized();
    send(sock, header_serialized, passl::protocol_header::sizeof_protocol_header(), 0);
    delete[] header_serialized;

    // Data iterator, we will use this to send our blocks
    passl::dblock_iterator iterator(client_pubkey.data(), client_pubkey.size(), header.d_section.block_size, 0, sizeof(uint32_t));

    iterator.iterate(
        [this](uint32_t crc32, unsigned char* data, size_t block_size) -> bool
        {
          int res = 0;
          res = send(sock, (unsigned char*)(&crc32), sizeof(uint32_t), 0);
          if (res < 0 || res != sizeof(uint32_t)) return false;
          res = send(sock, data, block_size, 0);
          if (res < 0 || res != block_size) return false;
          return true;
        });
  }

  client::~client()
  {
    close(sock);
    delete conn_addr;
  }
} // namespace passl
