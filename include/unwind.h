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
		const ucontext_t *uc = reinterpret_cast<const ucontext_t *>(sigcontext);
		// Copy all general purpose registers (x0-x28)
		for (int i = 0; i < 31; i++) {
			context->uc_mcontext.regs[i] = uc->uc_mcontext.regs[i];
		}
		context->uc_mcontext.sp = uc->uc_mcontext.sp; // SP
		context->uc_mcontext.pc = uc->uc_mcontext.pc; // PC
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
