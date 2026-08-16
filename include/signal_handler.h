#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H
#include <signal.h>

namespace signal_handler
{
  extern int signal;
  static void handler(int sig){signal = sig;}
  struct _sig_handler{_sig_handler();};
  static _sig_handler _handlr;
}
#endif
