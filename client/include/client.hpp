#ifndef PASSLCXX_HPP
#define PASSLCXX_HPP

#include <cstdint>

namespace passl
{
  class client
  {
    public:
      client();
      void connect(const char* address, uint8_t port);
      
    private:
      int fd=-1;
  };
}

#endif
