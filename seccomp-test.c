#define __USE_GNU
#define _GNU_SOURCE

#include <stdio.h>
#include <seccomp.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>

#include <sys/utsname.h> /* uname */


// x86_64 regs

#define REG_RESULT	REG_RAX
#define REG_SYSCALL	REG_RAX
#define REG_ARG0	REG_RDI
#define REG_ARG1	REG_RSI
#define REG_ARG2	REG_RDX
#define REG_ARG3	REG_R10
#define REG_ARG4	REG_R8
#define REG_ARG5	REG_R9


struct utsname unameDataGlobal;

void sigsys_handler(int signum, siginfo_t *info, void *ptr)
{
    struct utsname *buf;
    char *aarch64Str = "aarch64";

    ucontext_t *ctx = (ucontext_t *)(ptr);
    ctx->uc_mcontext.gregs[REG_RESULT] = 0;

    buf = (struct utsname *) ctx->uc_mcontext.gregs[REG_ARG0];
    memcpy(buf, &unameDataGlobal, sizeof(struct utsname));

    memset(buf->machine, 0, strlen(buf->machine));
    strncpy(buf->machine, aarch64Str, strlen(aarch64Str));

    return;
}

void setup_signals()
{
    static struct sigaction _sigact;

    memset(&_sigact, 0, sizeof(_sigact));
    _sigact.sa_sigaction = sigsys_handler;
    _sigact.sa_flags = SA_SIGINFO;

    sigaction(SIGSYS, &_sigact, NULL);
}

void printUtsname(struct utsname *buf)
{
    printf("  Syname: %s\n", buf->sysname);
    printf("  Nodename: %s\n", buf->nodename);
    printf("  Release: %s\n", buf->release);
    printf("  Version: %s\n", buf->version);
    printf("  Machine: %s\n\n", buf->machine);
}

int main(void)
{

  struct utsname unameData;

  setup_signals();
  printf("* Signals set up\n");

  int ret = uname(&unameDataGlobal);
  if(ret != 0){
    printf("Error getting original uname data\n");
    return -1;
  }

  printf("\n* Printing ORIGINAL uname data\n");
  printf("  ----------------------------\n");
  printUtsname(&unameDataGlobal);

  // Init the filter
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);

  // setup uname trap
  seccomp_rule_add(ctx, SCMP_ACT_TRAP, SCMP_SYS(uname), 0);

  // Build and load the filter
  seccomp_load(ctx);
  printf("* Uname Seccomp filter loaded\n");

  // Call uname
  printf("* Calling uname\n");
  memset(&unameData, 0, sizeof(struct utsname));
  ret = uname(&unameData);


  printf("\n* Printing uname data from EMULATED call\n");
  printf("  --------------------------------------\n");
  printUtsname(&unameData);
  printf("* EMULATED uname syscall ret value: %d\n", ret);

  return 0;
}

