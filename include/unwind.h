#ifndef UNWIND
#define UNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <string.h>
#include <cstring>
#include <stdio.h>
// #include "executable_segments.h"
class ExecutableSegments;
class ThreadUnwind
{
public:
  ThreadUnwind()
  {
  }

  ~ThreadUnwind()
  {
  }

  inline void reset()
  {
    memset(&context_, 0, sizeof(unw_context_t));
  }

bool unwind(void *sigcontext, uint64_t *buffer, uint8_t max_frame_size, uint8_t &real_frame_size,int tid, ExecutableSegments * executable_segments);

private:
  inline void extract_from_context(void *sigcontext)
  {
    unw_tdep_context_t *context = reinterpret_cast<unw_tdep_context_t *>(&context_);
#if defined(__aarch64__)
#include <sys/ucontext.h>
    const ucontext_t *uc = reinterpret_cast<const ucontext_t *>(sigcontext);
    //memcpy(context, uc, sizeof(ucontext_t)); 
    context->uc_link = uc->uc_link;
    context->uc_stack = uc->uc_stack;
    context->uc_sigmask = uc->uc_sigmask;
    context->uc_mcontext.fault_address = uc->uc_mcontext.fault_address;
    context->uc_mcontext.sp = uc->uc_mcontext.sp;
    context->uc_mcontext.pc = uc->uc_mcontext.pc;
    context->uc_mcontext.pstate = uc->uc_mcontext.pstate;
    std::memcpy(context->uc_mcontext.regs, uc->uc_mcontext.regs, sizeof(uc->uc_mcontext.regs));
    std::memcpy(context->uc_mcontext.__reserved, uc->uc_mcontext.__reserved, 4096 * sizeof(char));
#elif defined(__x86_64__)
#include <sys/ucontext.h>
    typedef struct ucontext ucontext_t;
    const ucontext_t *uc = (const ucontext_t *)sigcontext;
    context->uc_mcontext.gregs[REG_RBP] = uc->uc_mcontext.gregs[REG_RBP];
    context->uc_mcontext.gregs[REG_RSP] = uc->uc_mcontext.gregs[REG_RSP];
    context->uc_mcontext.gregs[REG_RIP] = uc->uc_mcontext.gregs[REG_RIP];
#endif
  }

private:
  unw_context_t context_;
};
#endif
