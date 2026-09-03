#ifndef PASSLCXX_HPP
#define PASSLCXX_HPP

#include <cstddef>
#include <cstdint>

struct sockaddr_in;

namespace passl
{
  class client
  {
    public:
      client();
      ~client();
      void connect(const char* address, uint32_t port);
      size_t key_bitsize = 3072;

    private:
      int sock = -1;
      sockaddr_in* conn_addr;
  };
} // namespace passl

#endif
