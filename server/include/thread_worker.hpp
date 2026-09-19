#ifndef THREAD_WORKER_HPP
#define THREAD_WORKER_HPP
#include "fatomic.hpp"
#include <cstddef>
#include <mutex>
#include <thread>

struct pollfd;

namespace passl
{
  struct session_data;

  class thread_worker
  {
    public:
      thread_worker();
      ~thread_worker();

      void add_client(int fd);
      void start();

      bool _shutdown = false;

    private:
      void remove_client(int fd);
      void handle_events();
      void client_handler();
      void resize_cap(size_t size);
      void retrieve_pubkey(session_data& client);
      void keygen_and_send(session_data& client, size_t keysize);
      pollfd* cpoll = nullptr;
      session_data* clients = nullptr;
      std::thread t;
      fatomic<size_t> client_count { 0 };
      fatomic<size_t> client_capacity { 2 };
      std::mutex client_mutex;
  };

} // namespace passl

#endif
