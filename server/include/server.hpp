#ifndef PASSLCXX_SERVER_HPP
#define PASSLCXX_SERVER_HPP
#include "stddef.h"
#include "thread_worker.hpp"
#include <cstdint>
#include <queue>

struct sockaddr_in;
struct pollfd;

typedef uint32_t in_addr_t;

namespace dutils
{
  class dbuffer;
}

namespace passl
{
  struct s_client;
  class server
  {
    public:
      server();
      server(unsigned int port, size_t thread_count);
      std::queue<std::pair<in_addr_t, dutils::dbuffer>> msg_que;
      void start();
      ~server();

    private:
      bool _shutdown = false;
      size_t max_clients = 3;
      int sock;

      sockaddr_in* addr = nullptr;

      // Admission poll
      int apoll = -1;
      thread_worker* workers = nullptr;
      size_t worker_count = 1;

      void connection_handler();
      void admit_client(int client_sock);
      void client_handler();
      static void throw_serrno(const char* msg);
  };
} // namespace passl
#endif
