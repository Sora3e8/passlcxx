#ifndef PASSLCXX_SERVER_HPP
#define PASSLCXX_SERVER_HPP
#include "stddef.h"
#include "thread_worker.hpp"

struct sockaddr_in;
struct pollfd;
typedef unsigned long int pthread_t;

namespace passl 
{
  struct s_client;
  class server 
  {
    public:
      server();
      server(unsigned int port,size_t thread_count);
      void start();
      ~server();

    private:
      bool _shutdown = false;
      size_t max_clients = 3;
      int sock;

      sockaddr_in *addr = nullptr;

      // Admission poll
      pollfd *apoll = nullptr;
      thread_worker* workers=nullptr;
      size_t worker_count=1;

      void connection_handler();
      void admit_client(int client_sock);
      void client_handler();
      static void throw_serrno(const char *msg);
  };
} // namespace passl
#endif
