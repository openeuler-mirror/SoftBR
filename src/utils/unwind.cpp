#include "unwind.h"
#include "executable_segments.h"
#include <libunwind.h>
#include <string.h>
#include <signal.h>
bool ThreadUnwind::unwind(void *sigcontext, uint64_t *buffer, uint8_t max_frame_size, uint8_t &real_frame_size,int tid, ExecutableSegments * executable_segments)
  {
    // DEBUG("tid %d unwind",tid);
    extract_from_context(sigcontext);
    real_frame_size = 0;
    unw_cursor_t cursor1;
    // int ret = unw_init_local(&cursor1, &context_);
    int ret = unw_init_local2(&cursor1, &context_, UNW_INIT_SIGNAL_FRAME);
    // DEBUG("unw_init_local UNW_REG_IP pc %#lx", get_pc(ut));
    if (ret < 0)
    {
      return false;
    }
   //TODO: check if the unwinded stack below is consistent with the stack collected by perf
    do
    {
      unw_word_t pc;
      ret = unw_get_reg(&cursor1, UNW_REG_IP, &pc);
      ERROR(" UNW_REG_IP pc %#lx", pc);
      if(buffer==nullptr){
        ERROR("rid %d buffer is nullptr cannot unwind",tid);
        return false;
      }
    
      if(!executable_segments->isAddressInExecutableSegment(pc)){
        break;
      }
      buffer[real_frame_size] = pc;
      ret = unw_step(&cursor1);   
      real_frame_size++;
    } while (ret > 0 && real_frame_size < max_frame_size);

    return true;
  }

