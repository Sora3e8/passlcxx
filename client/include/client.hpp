#ifndef PASSLCXX_HPP
#define PASSLCXX_HPP

#include "session_structs.hpp"
#include <cstddef>
#include <cstdint>

struct sockaddr_in;

namespace passl
{
  struct session_data_t;

  class client
  {
    public:
      client();
      ~client();
      void connect(const char* address, uint32_t port);
      session_data s_data;
      size_t key_bitsize = 3072;

    private:
      int sock = -1;
      sockaddr_in* conn_addr;
  };
} // namespace passl

#endif
