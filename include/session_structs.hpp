#ifndef PASSLCXX_SESSION_STRUCTS_HPP
#define PASSLCXX_SESSION_STRUCTS_HPP

#include "protocol_data.hpp"
#include "tancrypt/keyc.hpp"
#include "tancrypt/pkic.hpp"
#include <cstdint>

struct pollfd;

namespace passl
{
  enum class session_state : uint8_t
  {
    INVALID_STATE = 0,
    RET_HEADER,
    RET_DATA
  };

  enum session_phase : uint8_t
  {
    INVALID_PHASE = 0,
    ASYM_HANDSHAKE,
    SYM_HANDSHAKE,
    ENC_EXCHANGE
  };

  struct session_data
  {
      int fd = -1;
      bool has_update = false;
      session_phase phase = session_phase::INVALID_PHASE;
      session_state state = session_state::INVALID_STATE;
      tancrypt::RSA::pkic our_key;
      tancrypt::AES::keyc shared_secret;
      tancrypt::RSA::pkic foreign_key;
      dutils::dbuffer data;
      protocol_data::protocol_descriptor prot_descr;
  };
}
#endif
