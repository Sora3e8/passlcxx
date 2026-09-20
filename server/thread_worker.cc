#include "thread_worker.hpp"
#include "passl/protocol_sequence.hpp"
#include "protocol_data.hpp"
#include "session_structs.hpp"
#include "tancrypt/dutils.hpp"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <thread>
#include <uchar.h>
#include <unistd.h>
#include <utility>

inline uint32_t bswap32(uint32_t value)
{
  return (((value & 0xff000000) >> 24) | ((value & 0x000000ff) << 24) | ((value & 0x00ff0000) >> 8) | ((value & 0x0000ff00) << 8));
}

namespace passl
{

  thread_worker::thread_worker()
  {
    cpoll = new pollfd[client_capacity];
    clients = new session_data[client_capacity];

    for (size_t i = 0; i < client_capacity; i++)
    {
      // Marks member empty - (-1)
      cpoll[i].fd = -1;
      clients[i].fd = -1;
    }
  }

  void thread_worker::resize_cap(size_t size)
  {
    if (size < 1)
      return;

    pollfd* new_cpoll = new pollfd[size];
    std::move(cpoll, cpoll + std::min(size, (size_t)client_count), new_cpoll);

    session_data* new_clients = new session_data[size];
    std::move(clients, clients + std::min(size, (size_t)client_count), new_clients);

    delete[] cpoll;
    delete[] clients;

    cpoll = new_cpoll;
    clients = new_clients;
  }

  void thread_worker::add_client(int fd)
  {
    // std::lock_guard<std::mutex> lock(client_mutex);
    client_mutex.lock();

    // Expands the client_capacity by 2 if not enough space
    if (client_count + 1 > client_capacity) resize_cap(client_capacity + 2);

    // Initializes client member
    cpoll[client_count].fd = fd;
    cpoll[client_count].events = POLLIN | POLLHUP;
    clients[client_count].fd = fd;

    client_count++;

    client_mutex.unlock();
  }

  thread_worker::~thread_worker()
  {
    delete[] cpoll;
    delete[] clients;
  }

  void thread_worker::remove_client(int fd)
  {
    std::cout << "Thread worker client disconnect" << std::endl;
    bool target_lock = false;
    for (size_t i = 0; i < client_count; i++)
    {
      if (cpoll[i].fd == fd) target_lock = true;

      if (target_lock)
      {
        std::swap(cpoll[i], cpoll[i + 1]);
        std::swap(clients[i], clients[i + 1]);
      }
    }

    close(fd);
    cpoll[client_count].fd = -1;
    cpoll[client_count].revents = 0;

    clients[client_count].fd = -1;
    clients[client_count].our_key = tancrypt::RSA::pkic();
    clients[client_count].foreign_key = tancrypt::RSA::pkic();
    clients[client_count].data = { };
    clients[client_count].c_state = session_state::RET_PUBKEY;
    client_count += -1;
  }

  void thread_worker::handle_events()
  {
    for (size_t i = 0; i < client_count; i++)
    {
      char tmp; // Handles clientside disconnects
      if (cpoll[i].revents & POLLHUP || recv(cpoll[i].fd, &tmp, 1, MSG_PEEK | MSG_DONTWAIT) == 0) remove_client(cpoll[i].fd);

      if (cpoll[i].revents & POLLIN)
      {
        // Attempts to retrieve client's pubkey if not yet retrieved
        if (clients[i].c_state == session_state::RET_PUBKEY)
        {
          if (protocol_sequence::retrieve_pubkey(clients[i].fd, clients[i].foreign_key, clients[i].prot_data))
          {
            clients[i].c_state = session_state::INIT_KEYPAIR;
            std::cout << "Key retrieval succeeded!" << std::endl;
          }
          else
          {
            std::cout << "Key retrieval failed!" << std::endl;
            std::cout << protocol_data::prot_errstr(clients[i].prot_data.status) << std::endl;
            remove_client(clients[i].fd);
            continue;
          }
        }

        // Initializes key and sends if not ready - but this fires only when
        // client sends their key first!
        if (clients[i].c_state == session_state::INIT_KEYPAIR)
        {
          protocol_sequence::keygen_and_send(clients[i].fd, clients[i].our_key, 2048);
          clients[i].c_state = session_state::RET_PUBKEY;
        }
      }
    }
  }

  void thread_worker::client_handler()
  {
    while (!_shutdown)
    {
      client_mutex.lock();
      if (poll(cpoll, client_count, 0) > 0) handle_events();
      client_mutex.unlock();

      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

  void thread_worker::start()
  {
    this->t = std::thread(&thread_worker::client_handler, this);
  }

} // namespace passl
