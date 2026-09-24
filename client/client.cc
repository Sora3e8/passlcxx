#include "client.hpp"
#include "passl/protocol_sequence.hpp"
#include "protocol_sequence.hpp"
#include "session_structs.hpp"
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
    s_data.fd = socket(AF_INET, SOCK_STREAM, 0);
  }

  void client::connect(const char* address, uint32_t port)
  {
    using exchange_role = protocol_sequence::exchange_role;
    conn_addr = new sockaddr_in();
    conn_addr->sin_family = AF_INET;
    conn_addr->sin_port = htons(port);
    conn_addr->sin_addr.s_addr = inet_addr(address);

    int res = ::connect(s_data.fd, (const sockaddr*)conn_addr, sizeof(*conn_addr));
    if (res < 0)
    {
      std::cout << "[passl::client] Could not connect Error:" << errno << ", "
                << strerror(errno) << std::endl;
      return;
    }

    protocol_sequence::keygen_and_send(s_data.fd, s_data.our_key, key_bitsize);
    bool succ = protocol_sequence::retrieve_pubkey(s_data.fd, s_data.foreign_key, s_data.prot_descr);
    if (succ) std::cout << "Pubkey received" << std::endl;
    protocol_sequence::sharedfraggen_and_send(s_data.fd, &s_data.shared_secret, exchange_role::client);
    succ = protocol_sequence::retrieve_sharedfrag(s_data.fd, &s_data.shared_secret, exchange_role::client, s_data.prot_descr);
    if (succ) std::cout << "Shared secret fragment received" << std::endl;
  }

  client::~client()
  {
    close(s_data.fd);
    if (conn_addr != nullptr) delete conn_addr;
  }
} // namespace passl
