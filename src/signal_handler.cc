#include "signal_handler.h"
namespace signal_handler
{
  int signal = 0;
  _sig_handler::_sig_handler(){::signal(SIGINT,handler);}
}
