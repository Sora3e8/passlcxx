#include "thread_worker.hpp"
#include "fatomic.hpp"
#include "passl/protocol_sequence.hpp"
#include "protocol_sequence.hpp"
#include "session_structs.hpp"
#include "tancrypt/dutils.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/epoll.h>
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
    // Using raw heap to prevent needless re-initialization
    cpoll = epoll_create1(0);
    cpoll_revents = new epoll_event[cpoll_revsize];
    cpoll_listen_events = new epoll_event;
    cpoll_listen_events->events = EPOLLIN | EPOLLHUP;

    clients = new session_data[client_capacity];
    for (size_t i = 0; i < client_capacity; i++)
    {
      // Marks member empty - (-1)
      clients[i].fd = -1;
    }
  }

  void thread_worker::resize_cap(size_t size)
  {
    if (size < 1)
      return;

    session_data* new_clients = new session_data[size];
    std::move(clients, clients + std::min(size, (size_t)client_count), new_clients);

    delete[] clients;

    clients = new_clients;
    this->client_capacity = size;
  }

  void thread_worker::add_client(int fd)
  {
    // Expands the client_capacity by 2 if not enough space
    if (client_count + 1 > client_capacity)
    {
      client_mutex.lock();
      resize_cap(client_capacity + 2);
      client_mutex.unlock();
    }

    cpoll_listen_events->data.ptr = (void*)&clients[client_count];
    // Adds client to kernel's epoll watchlist
    epoll_ctl(cpoll, EPOLL_CTL_ADD, fd, cpoll_listen_events);

    // Initializes client
    clients[client_count].fd = fd;
    clients[client_count].phase = session_phase::ASYM_HANDSHAKE;
    clients[client_count].state = session_state::RET_HEADER;

    // Updates client count
    client_count++;
  }

  thread_worker::~thread_worker()
  {
    delete cpoll_listen_events;
    delete[] cpoll_revents;
    delete[] clients;
    this->t.join();
    close(cpoll);
  }

  void thread_worker::remove_client(int fd)
  {
    std::cout << "Thread worker client disconnect" << std::endl;
    bool target_lock = false;
    for (size_t i = 0; i < client_count; i++)
    {
      if (clients[i].fd == fd) target_lock = true;

      if (target_lock)
      {
        std::swap(clients[i], clients[i + 1]);
      }

      // Update pointer mapping
      cpoll_listen_events->data.ptr = (void*)&clients[i];
      epoll_ctl(cpoll, EPOLL_CTL_MOD, clients[i].fd, cpoll_listen_events);
    }

    // Removes the client from kernel's epoll watchlist
    epoll_ctl(cpoll, EPOLL_CTL_DEL, fd, nullptr);
    close(fd);

    clients[client_count].fd = -1;
    clients[client_count].our_key = tancrypt::RSA::pkic();
    clients[client_count].foreign_key = tancrypt::RSA::pkic();
    clients[client_count].data = { };
    clients[client_count].phase = session_phase::INVALID_PHASE;
    clients[client_count].state = session_state::INVALID_STATE;
    client_count += -1;
  }

  void thread_worker::handle_events(size_t event_count)
  {
    using exchange_role = protocol_sequence::exchange_role;

    for (size_t i = 0; i < event_count; i++)
    {

      // Skip the pass if no events
      if (!(cpoll_revents[i].events & EPOLLIN)) continue;

      // Handle disconnects
      char tmp;

      bool is_disconnect = (cpoll_revents[i].events & EPOLLHUP || recv(cpoll_revents[i].data.fd, &tmp, 1, MSG_PEEK | MSG_DONTWAIT) == 0);
      if (is_disconnect) remove_client(cpoll_revents[i].data.fd);
      // Handle disconnects - end

      // Retrieve session_data_ptr
      session_data* client_ptr = (session_data*)cpoll_revents[i].data.ptr;

      // Retrieves header and saves data to protocol descriptor, kicks client if invalid
      if (client_ptr->state == session_state::RET_HEADER)
      {
        if (protocol_sequence::retrieve_header(client_ptr->fd, client_ptr->prot_descr))
        {
          clients[i].state = session_state::RET_DATA;
        }
        else
        {
          remove_client(client_ptr->fd);
          continue;
        }
      }

      if (client_ptr->state == session_state::RET_DATA)
      {
        bool res = false;
        switch (client_ptr->phase)
        {
          case session_phase::ASYM_HANDSHAKE:
            res = protocol_sequence::retrieve_pubkey(client_ptr->fd, client_ptr->foreign_key, client_ptr->prot_descr);
            if (res)
            {
              protocol_sequence::keygen_and_send(client_ptr->fd, client_ptr->our_key, 3072);
              client_ptr->phase = session_phase::SYM_HANDSHAKE;
              client_ptr->state = session_state::RET_HEADER;
            }
            break;

          case session_phase::SYM_HANDSHAKE:
            res = protocol_sequence::retrieve_sharedfrag(client_ptr->fd, &client_ptr->shared_secret, exchange_role::server, client_ptr->prot_descr);
            if (res)
            {
              protocol_sequence::sharedfraggen_and_send(client_ptr->fd, &client_ptr->shared_secret, exchange_role::server);
              client_ptr->phase = session_phase::ENC_EXCHANGE;
              client_ptr->state = session_state::RET_HEADER;
            }
            break;

          default:
            break;
        }
        if (!res)
        {
          std::cout << protocol_data::prot_errstr(client_ptr->prot_descr.status) << std::endl;
          remove_client(client_ptr->fd);
          continue;
        }
      }
    }
  }

  void thread_worker::client_handler()
  {
    while (!_shutdown)
    {
      int update_count = epoll_wait(cpoll, cpoll_revents, cpoll_revsize, cpoll_timeout_ms);

      if (update_count > 0)
      {
        client_mutex.lock();
        handle_events(update_count);
        client_mutex.unlock();
      }
    }
  }

  void thread_worker::start()
  {
    this->t = std::thread(&thread_worker::client_handler, this);
  }

} // namespace passl
