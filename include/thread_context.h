#ifndef THREAD_CONTEXT
#define THREAD_CONTEXT

#include "buffer_manager.h"
#include "consts.h"
#include "dr_api.h"
#include "dr_tools.h"
#include "log.h"
#include "stack_lbr_utils.h"
#include "unwind.h"
#include <cstdint>
#include <linux/perf_event.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <map>
enum THREADSTATE {
    init = 0,
    contextNull = 0x1,
    context = 0x2,
    bufferNull = 0x4,
    buffer = 0x8,
    sampleOpen = 0x10,
    sampling = 0x20,
    sampled = 0x40,
    sampleClose = 0x80,
    breakpointOpen = 0x100,
    breakpointChange = 0x200,
    breakpointing = 0x400,
    breakpointed = 0x800,
    breakpointClose = 0x1000,
    end
};
extern std::map<pid_t, int> threadState; 
extern std::map<pid_t, int> threadNum;
typedef struct _branch
{
  uintptr_t from_addr;
  uintptr_t to_addr; // if to_addr is UNKNOWN_ADDR, it means this branch needs a breakpoint
} branch;

typedef struct _perf_ip_sample
{
  struct perf_event_header header;
  uint64_t ip;
} perf_ip_sample;

uint64_t get_mmap_len();

class ThreadContext
{
public:
  ThreadContext():  handler_num(0), tid_(-1)
  {
    DEBUG("init the ThreadContext of thread %d", tid_);
    //TODO:uncommented the following line will cause seg fault
    thread_dr_context_ = dr_standalone_init();
    
#if defined(__x86_64__)
    if (!dr_set_isa_mode(thread_dr_context_, DR_ISA_AMD64, nullptr))
#elif defined(__aarch64__)
    if (!dr_set_isa_mode(thread_dr_context_, DR_ISA_ARM_A64, nullptr))
#endif
    {
      ERROR("fail to set the isa mode.");
    }

    thread_stack_lbr_entry_.reset();
  }

  ~ThreadContext()
  {
  }
  void thread_context_init() {
      thread_dr_context_ = dr_standalone_init();
#if defined(__x86_64__)
      if (!dr_set_isa_mode(thread_dr_context_, DR_ISA_AMD64, nullptr))
#elif defined(__aarch64__)
      if (!dr_set_isa_mode(thread_dr_context_, DR_ISA_ARM_A64, nullptr))
#endif
      {
          ERROR("fail to set the isa mode.");
      }

      thread_stack_lbr_entry_.reset();
      reset_branch();
      branch_dyn_cnt_ = 0;
      branch_static_cnt_ = 0;
      drop_cnt_ = 0;
  }

  void destroy()
  {
    reset_entry();
    thread_buffer_ = nullptr;
    state_ = thread_state::CLOSED;
  }

  void reset() {
    stack_lbr_entry_reset();
    reset_branch();
  }
  void set_tid(pid_t tid) {
    tid_ = tid;
  }
  void reset_entry()
  {
    drop_cnt_ += thread_stack_lbr_entry_.get_branch_size();
    INFO("the thread %d drops %d branches",tid_, drop_cnt_);
    thread_stack_lbr_entry_.reset();
    reset_branch();
  }

  bool set_buffer_manager(BufferManager *buffer_manager)
  {
    buffer_manager_ = buffer_manager;
    thread_buffer_ = buffer_manager_->bufferMap[tid_];
    if (thread_buffer_ == nullptr) {
      return false;
    }
    return true;
  }
  void thread_context_destroy() {
    destroy();
    dr_standalone_exit();
    thread_dr_context_ = nullptr;
  }
  void thread_stop() {
    close_perf_sampling_event(threadState[tid_]);
    close_perf_breakpoint_event(threadState[tid_]);
    state_ = CLOSED;
  }

  void init_perf_breakpoint_event(int &threadState);
  /** thread state **/
  bool is_sampling() const { return state_ == thread_state::SAMPLING; }

  bool is_breakpointing() const { return state_ == thread_state::BREAKPOINT; }

  pid_t get_tid() const { return tid_; }

  void *get_dr_context() const { return thread_dr_context_; }
  
  instr_t* get_instr() { return d_insn_;}

  /** thread perf events state/control **/
  int get_sampling_fd() const { return sampling_fd_; }

  int get_breakpoint_fd() const { return bp_fd_; }

  uint64_t get_breakpoint_addr() const { return bp_addr_; }

  void set_breakpoint_addr(uint64_t bp_addr) { bp_addr_ = bp_addr; }

  void open_perf_sampling_event(int &threadState);
  void handler_num_inc() {
      handler_num++;
  }
  void handler_num_dec() {
      handler_num--;
  }
  int get_handler_num() {
      return handler_num.load();
  }


  void enable_perf_sampling_event(int &threadState)
  {
    if (threadState & breakpointing) {
      INFO("sample when breakpoint");
      return;
    }
    if(state_ == thread_state::CLOSED)
      return;
    state_ = thread_state::SAMPLING;

    if (sampling_fd_ == -1)
    {
      //WARNING("samping event is closed.");
      return;
    }
    if (ioctl(this->sampling_fd_, PERF_EVENT_IOC_ENABLE, 0) != 0)
    {
      perror("PERF_EVENT_IOC_ENABLE");
      ERROR("fail to enable perf sampling event");
    }
    if (threadState & sampled) {
      threadState = threadState ^ sampled;
    }
    threadState = threadState | sampling;
    threadNum[tid_]++;
  }

  void disable_perf_sampling_event(int &threadState)
  {
    if (threadState & sampling) {
      threadState = threadState ^ sampling;
    }
    threadState = threadState | sampled;
    if (sampling_fd_ == -1)
    {
      ERROR("samping event is closed.");
      return;
    }

    if (ioctl(sampling_fd_, PERF_EVENT_IOC_DISABLE, 0) != 0)
    {
      perror("ioctl(PERF_EVENT_IOC_DISABLE)");
      WARNING("fail to disable perf sampling event");
      return;
    }
  }
  void enable_perf_breakpoint_event(int &threadState) {
    state_ = thread_state::BREAKPOINT;
    if (threadState & sampling) {
      INFO("breakpoint when sampling a");
      return;
    }
    if (bp_fd_ == -1 || bp_addr_ == UNKNOWN_ADDR) {
      WARNING("breakpoint event is closed.");
      return;
    }
    if (ioctl(this->bp_fd_, PERF_EVENT_IOC_ENABLE, 0) != 0) {
      // TODO: data race, the profiler thread may close the bp_fd_
      WARNING("PERF_EVENT_IOC_ENABLE");
      return;
    }
    //INFO("tid %d enable_perf_breakpoint_event tid is  state %d", tid_, threadState);
    if (threadState & breakpointed) {
      threadState = threadState ^ breakpointed;
    }
    threadState = threadState | breakpointing;
  }
  void disable_perf_breakpoint_event(int &threadState) {
    if (bp_fd_ == -1) {
        INFO("breakpoint event is closed.");
        return;
    }
    if (ioctl(bp_fd_, PERF_EVENT_IOC_DISABLE, 0) != 0) {
        WARNING("ioctl(PERF_EVENT_IOC_DISABLE)");
        INFO("fail to disable perf breakpoint event");
        return;
    }
    if (threadState & breakpointing) {
    threadState = threadState ^ breakpointing;
    }
    threadState = threadState | breakpointed;
  }
  void close_perf_sampling_event(int &threadState)
  {
    if (sampling_fd_ == -1)
    {
      ERROR("samping event is closed.");
      return;
    }

    if (close(sampling_fd_) != 0)
    {
      perror("close");
      ERROR("perf sampling event  closed failed ");
      return;
    }

    sampling_fd_ = -1;
    if (threadState & sampleOpen) {
      threadState = threadState ^ sampleOpen;
    }
    if (threadState & sampling) {
      threadState = threadState ^ sampling; 
    }
    if (threadState & sampled) {
      threadState = threadState ^ sampled; 
    }
    threadState = threadState | sampleClose;
    return;
  }
  void change_perf_breakpoint_event(uint64_t addr, int &threadState);
  // breakpoint event is created every time, so we don't have a 'disable_perf_breakpont_event'
  void close_perf_breakpoint_event(int &threadState)
  {
    if (bp_fd_ == -1)
    {
      WARNING("breakpoint event is closed.");
      return;
    }
    bp_addr_ = UNKNOWN_ADDR;
    state_ = thread_state::SAMPLING;

    

    if (close(bp_fd_) != 0)
    {
      perror("close");
      WARNING("fail to close perf sampling event");
      bp_fd_ = -1;
      return;
    }
    if (threadState & breakpointOpen) {
      threadState = threadState ^ breakpointOpen;
    }
    if (threadState & breakpointChange) {
      threadState = threadState ^ breakpointChange;
    }
    if (threadState & breakpointing) {
      threadState = threadState ^ breakpointing;
    }
    if (threadState & breakpointed) {
      threadState = threadState ^ breakpointed;
    }
    threadState = threadState | breakpointClose;
    WARNING("close perf bp event %d", tid_);
    bp_fd_ = -1;
    return;
  }
  /** tracing branch state **/
  branch get_branch() const { return cur_branch_; }

  // reset the traced branch as initial state
  void reset_branch()
  {
    cur_branch_.from_addr = UNKNOWN_ADDR;
    cur_branch_.to_addr = UNKNOWN_ADDR;
  }

  void set_from_addr(uint64_t from_addr) { cur_branch_.from_addr = from_addr; }

  void set_to_addr(uint64_t to_addr) { cur_branch_.to_addr = to_addr; }

  bool stack_lbr_entry_full();

  void stack_lbr_entry_reset();

  void add_to_stack_lbr_entry();

  StackLBREntry *get_entry() { return &thread_stack_lbr_entry_; }

  void reset_unwind() { thread_unwind_util_.reset(); }
  

  bool unwind( void *sigcontext, uint64_t *buffer, uint8_t max_frame_size, uint8_t &real_frame_size,int pid,ExecutableSegments * executable_segments)//pid for debug
  {
    return thread_unwind_util_.unwind( sigcontext, buffer, max_frame_size, real_frame_size,pid,executable_segments);
  }

  /** branch tracing statistics **/
  void add_static_branch() { 
    branch_static_cnt_++; 
  }

  void add_dynamic_branch() { 
    branch_dyn_cnt_++; 
    }
public:
  pid_t tid_{0};
  int sampleCounter_{0};
  int tempcounter_{0};
  int callcounter_{0};
  int branchcounter_{0};
  int retcounter_{0};
  int changeDefault_{0};
  int sampling_period{50000*5};
  int breakpointNum{0};
  typedef enum _thread_state
  {
    SAMPLING = 1,
    BREAKPOINT,
    CLOSED,
  } thread_state;
  std::atomic<thread_state> state_{thread_state::CLOSED};
  std::atomic<int> handler_num;
  std::shared_ptr<StackLBRBuffer> thread_buffer_{nullptr};
private:
  void *thread_dr_context_{nullptr};
  instr_t * d_insn_;
  uint64_t bp_addr_{UNKNOWN_ADDR};
  ThreadUnwind thread_unwind_util_;
  StackLBREntry thread_stack_lbr_entry_; //
  BufferManager *buffer_manager_{nullptr};

  // perf_events related data structure
  int sampling_fd_{-1}; // the fd of the sampling events, -1 for invalid
  int bp_fd_{-1};       // the fd of breakpoint event, -1 for invalid
  int drop_cnt_{0};
  int branch_static_cnt_{0};
  int branch_dyn_cnt_{0};
  branch cur_branch_{.from_addr = UNKNOWN_ADDR, .to_addr = UNKNOWN_ADDR};
};
#endif