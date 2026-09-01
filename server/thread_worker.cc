#include "thread_worker.hpp"
#include "passl/protocol.hpp"
#include "s_client.hpp"
#include "tancrypt/dutils.hpp"
#include <algorithm>
#include <chrono>
#include <cstddef>
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
    clients = new s_client[client_capacity];

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

    s_client* new_clients = new s_client[size];
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
    clients[client_count].server_key = tancrypt::RSA::pkic();
    clients[client_count].client_key = tancrypt::RSA::pkic();
    clients[client_count].data = { };
    clients[client_count].c_state = s_clistate::RET_PUBKEY;
    client_count += -1;
  }

  void thread_worker::keygen_and_send(s_client& client, size_t keysize)
  {
    client.server_key.generate_keypair(keysize);
    client.c_state = s_clistate::RET_HEADER;
  }

  void thread_worker::retrieve_pubkey(s_client& client)
  {
    unsigned char p_header[sizeof_protocol_header()];

    // Size with -1 error guard
    int rec_size = recv(client.fd, &p_header, sizeof(p_header), 0);
    if (!(rec_size > 0)) return;
    protocol_descriptor descriptor;
    if (!protocol_header::read_descriptor(p_header, rec_size, &descriptor))
    {
      std::cout << "Validation failed!" << std::endl;
      std::cout << passl::prot_errstr(descriptor.status) << std::endl;
    }
    else
    {
      std::cout << "Validation succeeded!" << std::endl;
    }
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
        if (clients[i].c_state == s_clistate::RET_PUBKEY) retrieve_pubkey(clients[i]);

        // Initializes key and sends if not ready - but this fires only when
        // client sends their key first!
        if (clients[i].c_state == s_clistate::INIT_KEYPAIR) keygen_and_send(clients[i], 2048);
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
