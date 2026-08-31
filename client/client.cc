#include "client.hpp"
#include "header_structs.hpp"
#include "tancrypt/rsa.hpp"
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

    // Initialize keypair and extract pubkey
    tancrypt::RSA::pkic client_key;
    client_key.generate_keypair(3072);
    dutils::dbuffer client_pubkey = client_key.getPubDER();

    // Prepare header to carry the pubkey
    passl::protocol_header header(1, client_pubkey.size(), client_pubkey.size());

    unsigned char* header_serialized = header.get_serialized();
    send(sock, header_serialized, sizeof_protocol_header(), 0);
    delete[] header_serialized;
  }

  client::~client()
  {
    close(sock);
    delete conn_addr;
  }
}
