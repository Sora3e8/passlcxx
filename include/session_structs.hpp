#ifndef PASSLCXX_SESSION_STRUCTS_HPP
#define PASSLCXX_SESSION_STRUCTS_HPP

#include "protocol_data.hpp"
#include "tancrypt/pkic.hpp"

struct pollfd;

namespace passl
{
  enum class session_state : int
  {
    INVALID_STATE = -1,
    RET_PUBKEY,
    INIT_KEYPAIR,
    RET_HEADER,
    PENDING_DATA
  };

  struct session_data
  {
      int fd = -1;
      bool has_update = false;
      session_state state = session_state::INVALID_STATE;
      tancrypt::RSA::pkic our_key;
      tancrypt::RSA::pkic foreign_key;
      dutils::dbuffer data;
      protocol_data::protocol_descriptor prot_descr;
  };
}
#endif
