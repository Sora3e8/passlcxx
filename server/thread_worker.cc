#include "thread_worker.hpp"
#include "fatomic.hpp"
#include "passl/protocol_sequence.hpp"
#include "protocol_data.hpp"
#include "protocol_sequence.hpp"
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
    this->client_capacity = size;
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
    clients[client_count].phase = session_phase::ASYM_HANDSHAKE;
    clients[client_count].state = session_state::RET_HEADER;

    client_count++;

    client_mutex.unlock();
  }

  thread_worker::~thread_worker()
  {
    delete[] cpoll;
    delete[] clients;
    this->t.join();
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
    clients[client_count].phase = session_phase::INVALID_PHASE;
    clients[client_count].state = session_state::INVALID_STATE;
    client_count += -1;
  }

  void thread_worker::handle_events()
  {
    using exchange_role = protocol_sequence::exchange_role;

    for (size_t i = 0; i < client_count; i++)
    {
      if (!(cpoll[i].revents & POLLIN)) continue;

      char tmp; // Handles clientside disconnects
      if (cpoll[i].revents & POLLHUP || recv(cpoll[i].fd, &tmp, 1, MSG_PEEK | MSG_DONTWAIT) == 0) remove_client(cpoll[i].fd);

      // Retrieves header and saves data to protocol descriptor, kicks client if invalid
      if (clients[i].state == session_state::RET_HEADER)
      {
        if (protocol_sequence::retrieve_header(clients[i].fd, clients[i].prot_descr))
        {
          clients[i].state = session_state::RET_DATA;
        }
        else
        {
          remove_client(clients[i].fd);
          continue;
        }
      }

      if (clients[i].state == session_state::RET_DATA)
      {
        bool res = false;
        switch (clients[i].phase)
        {
          case session_phase::ASYM_HANDSHAKE:
            res = protocol_sequence::retrieve_pubkey(clients[i].fd, clients[i].foreign_key, clients[i].prot_descr);
            if (res)
            {
              protocol_sequence::keygen_and_send(clients[i].fd, clients[i].our_key, 3072);
              clients[i].phase = session_phase::SYM_HANDSHAKE;
              clients[i].state = session_state::RET_HEADER;
            }
            break;

          case session_phase::SYM_HANDSHAKE:
            res = protocol_sequence::retrieve_sharedfrag(clients[i].fd, &clients[i].shared_secret, exchange_role::server, clients[i].prot_descr);
            if (res)
            {
              protocol_sequence::sharedfraggen_and_send(clients[i].fd, &clients[i].shared_secret, exchange_role::server);
              clients[i].phase = session_phase::ENC_EXCHANGE;
              clients[i].state = session_state::RET_HEADER;
            }
            break;

          default:
            break;
        }
        if (!res)
        {
          std::cout << protocol_data::prot_errstr(clients[i].prot_descr.status) << std::endl;
          remove_client(clients[i].fd);
          continue;
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
