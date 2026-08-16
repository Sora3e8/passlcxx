#include "server.hpp"
#include "s_client.hpp"
#include "tancrypt/rsa.hpp"
#include <asm-generic/socket.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal_handler.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <system_error>
#include <unistd.h>

namespace passl
{
  server::server() { }

  inline uint64_t bswap64(uint64_t value)
  {
    return ((value & 0xff00000000000000) >> 56 | (value & 0x00ff000000000000) >> 40 | (value & 0x0000ff0000000000) >> 24 | (value & 0x000000ff00000000) >> 8 | (value & 0x00000000ff000000) << 8 | (value & 0x0000000000ff0000) << 24 | (value & 0x000000000000ff00) << 40 | (value & 0xff000000000000ff) << 56);
  }

  server::server(unsigned int port, size_t thread_count)
  {
    // Socket initialization
    sock = socket(AF_INET, SOCK_STREAM, 0);
    int reuse_addr = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));

    if (sock < 0) throw_serrno("[passl::server] Could not create socket");

    // Admission poll
    apoll = new pollfd();
    apoll->fd = sock;
    apoll->events = POLLIN;

    // Address initialization
    addr = new sockaddr_in();
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    addr->sin_addr.s_addr = htonl(INADDR_ANY);
  }

  server::~server()
  {
    close(sock);
    if (addr != nullptr) delete addr;
    if (apoll != nullptr) delete apoll;
    if (workers != nullptr) delete[] workers;
  }

  void server::start()
  {
    workers = new thread_worker[worker_count];
    for (size_t i = 0; i < worker_count; i++) workers[i].start();

    if (bind(sock, (sockaddr*)addr, sizeof(*addr))) throw_serrno("[passl::server::start] Failed to start server");
    if (listen(sock, max_clients)) throw_serrno("[passl::server::start] Failed to start listening");

    connection_handler();
  }

  void server::connection_handler()
  {

    while (!_shutdown)
    {
      if (poll(apoll, 1, 10) > 0 && apoll->revents & POLLIN)
      {
        int client_sock = accept(sock, NULL, NULL);
        if (client_sock > 0) admit_client(client_sock);
      }

      if (signal_handler::signal & SIGINT)
      {
        std::cout << "Interrupt detected" << std::endl;
        for (size_t i = 0; i < worker_count; i++)
        {
          workers[i]._shutdown = true;
        }
        _shutdown = true;
      }
    }
  }

  void server::admit_client(int client_sock)
  {
    std::cout << "Client admission trigg" << std::endl;
    this->workers[0].add_client(client_sock);
  }

  void server::throw_serrno(const char* msg)
  {
    throw std::system_error(errno, std::generic_category(), msg);
  }

} // namespace passl
