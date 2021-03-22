
#include <signal.h>
#include <execinfo.h>
#include "debug.h"
#include "main.h"

void sigsegvHandler(int sig, siginfo_t *info, void *secret)
{
  UNUSED(secret);
  UNUSED(info);

  log_info("crashed by signal: %d, si_code: %d", sig, info->si_code);
  if (sig == SIGSEGV || sig == SIGBUS)
  {
    log_info("Accessing address: %p", (void *)info->si_addr);
  }
  if (info->si_pid != -1)
  {
    log_info("Killed by PID: %ld, UID: %d", (long)info->si_pid, info->si_uid);
  }
  /*
  * stacktrace
  */
  void *trace[100];
  size_t trace_size = 0;
  trace_size = backtrace(trace, 100);
  log_err("\n-- STACK TRACE ---\n");
  backtrace_symbols_fd(trace, trace_size, STDOUT_FD);

  fflush(stdout);
  fflush(stderr);
}
void sig_init()
{
  /*
  * crashlog part
  */
  struct sigaction act;

  act.sa_flags = 0;

  sigaction(SIGTERM, &act, NULL);
  sigaction(SIGINT, &act, NULL);
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_NODEFER | SA_RESETHAND | SA_SIGINFO;
  act.sa_sigaction = sigsegvHandler;
  // act.sa_handler = sigShutdownHandler;
  sigaction(SIGSEGV, &act, NULL);
  sigaction(SIGBUS, &act, NULL);
  sigaction(SIGFPE, &act, NULL);
  sigaction(SIGILL, &act, NULL);
  sigaction(SIGABRT, &act, NULL);
}