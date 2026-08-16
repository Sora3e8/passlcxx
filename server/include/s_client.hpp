#ifndef PASSLCXX_SCLIENT_HPP
#define PASSLCXX_SCLIENT_HPP

#include "tancrypt/pkic.hpp"

struct pollfd;

namespace passl
{
  enum class s_clistate: int
  {
    INIT_KEYPAIR = -1,
    RET_PUBKEY = 0,
    RET_HEADER = 1,
    PENDING_DATA = 2,
  };
  
  struct s_client
  {
    int fd=-1;
    bool has_update=false;
    s_clistate c_state=s_clistate::INIT_KEYPAIR;
    tancrypt::RSA::pkic server_key;
    tancrypt::RSA::pkic client_key;
    dutils::dbuffer data;
  };
}
#endif
