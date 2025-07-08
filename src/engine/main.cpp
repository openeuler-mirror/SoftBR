#define _GNU_SOURCE
#include "executable_segments.h"
#include "buffer_manager.h"
#include "utils.h"
#if defined(__x86_64__)
#include <bits/siginfo.h>
#endif

#include <cassert>
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <shared_mutex>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <thread>
#include <ucontext.h>
#include <unistd.h>
#include <unordered_map>

enum MAINTHREADSTATE {
    mainstart = 0x1,
    sendstop = 0x2,
    mainend
};
std::atomic<int> mainThread(mainstart);
constexpr std::size_t MAX_THREAD_NUM = 96;
constexpr std::size_t MAX_BREAKPOINT_NUM = 100;
constexpr std::size_t SOFTLBR_TIEM = 1000;
ThreadContext thread_context[MAX_THREAD_NUM];
thread_local ThreadContext *thread_local_context_ = nullptr;
thread_local pid_t threadtid = 0;
std::map<pid_t, int> threadState;
std::map<pid_t, int> threadNum; 
std::map<pid_t, int> sampleNum;
std::map<pid_t, int> breakpointNum;
thread_local int n = 0;
ExecutableSegments *executable_segments = nullptr;
BufferManager* buffer_manager = nullptr;

void sampling_handler(int signum, siginfo_t *info, void *ucontext);

void breakpoint_handler(int signum, siginfo_t *info, void *ucontext);

bool find_next_unresolved_branch(ThreadContext &tcontext, ucontext_t *uc, uint64_t pc);

void signal_prehandle(sigset_t &new_set, sigset_t &old_set);

void signal_posthandle(sigset_t &old_set);

void preload_main();

void not_reset_entry(void *ucontext);
 
/**
 * iterate instructions from `pc`.
 * If instruction is not cti, keep iterating;
 * If instruction is cti
 *    If instruction can be evaluated statically(jmp, call), add to stack_lbr_entry
 *    Else return false to set a breakpoint
 * ATTENTION:
 * For the last trace, a breakpoint is set to get the call stack.
 */
bool find_next_unresolved_branch(ThreadContext &tcontext, ucontext_t *uc, uint64_t pc)
{
    while (true)
    {
        //TODO caculate the length of the code to resolve
        int length = INT32_MAX;//executable_segments->getExecutableSegmentSize(pc);
        
        bool found = find_next_branch(tcontext, uc, pc, length);//set from addr
        if (!found)
        {
            WARNING("Fail to find a branch until the end of the code from %#lx.", pc);
            return false;
        }

        ucontext_t _{}; // for statical evaluation, ucontext is unnecessary
        auto [target, taken] = check_branch_if_taken(tcontext, _, true);

        // handle the breakpoint since the branch can't be evaluated statically
        if (target == UNKNOWN_ADDR)
        {
            // DEBUG("Should set the breakpoint");
            return true;
        }

        // branch is statically taken
        if (taken)
        {
            // DEBUG("Branch is taken unconditionally");
            tcontext.set_to_addr(target);
            tcontext.add_to_stack_lbr_entry();
            if (tcontext.stack_lbr_entry_full()) // last trace
            {
                // DEBUG("stack lbr entry is full, we set the final breakpoint for the call stack");
                return true;
            }
        }

        pc = target;
    }

    assert(0 && "never hit");
    return false;
}

void not_reset_entry(void *ucontext) {
   uint8_t real_frame_size = 0;
    if (thread_local_context_ == nullptr) {
        INFO("not_reset_entry thread_local_context_ is nullptr");
        return;
    }
    if (thread_local_context_->get_entry()->get_branch_size() == 0) {
        return;
    }
    thread_local_context_->reset_unwind();
    if (!thread_local_context_->unwind(ucontext, thread_local_context_->get_entry()->get_stack_buffer(), MAX_FRAME_SIZE, real_frame_size,thread_local_context_->get_tid(),executable_segments));
    {
        ERROR("fail to get the call stack");
    }
    WARNING("successfully unwind %d", threadtid);
    thread_local_context_->get_entry()->set_stack_size(real_frame_size);
    thread_local_context_->reset();
}

void breakpoint_handler(int signum, siginfo_t *info, void *ucontext)
{
    if (mainThread.load() & sendstop) {
        thread_local_context_->disable_perf_breakpoint_event(threadState[threadtid]);
        return;
    }
    if (info == nullptr || ucontext == nullptr) {
        INFO("breakpoint_handler info or ucontext is nullptr");
        return;
    }
    if (threadState[threadtid] & sampling) {
        if (threadState[threadtid] & breakpointing) {
            INFO("threadtid %d a breakpoint when sampling state %d", threadtid, threadState[threadtid]);
        }
        return;
    }
    if (thread_local_context_ == nullptr) {
        INFO("breakpoint_handler thread_local_context_ is nullptr");
        return;
    }
    thread_local_context_->handler_num_inc();
    if (mainThread.load() & sendstop) {
        thread_local_context_->handler_num_dec();
        thread_local_context_->disable_perf_breakpoint_event(threadState[threadtid]);
        return;
    }
    thread_local_context_->disable_perf_breakpoint_event(threadState[threadtid]);
    // /**
    //  * preconditions:
    //  * 1. thread is in breakpoint mode
    //  * 2. fd triggering event is bp_fd_
    //  * 3. address triggering event is bp_addr_
    //  * 4. address triggering event must be br.from_addr
    //  */
    if (!thread_local_context_->is_breakpointing())
    {
        if (thread_local_context_->is_sampling()) {
        ERROR("thread-id %d: breakpoint hit when the thread is in sampling");
        } else {
        ERROR("thread-id %d: breakpoint hit when the thread is in closed");
        }
	    not_reset_entry(ucontext);
        thread_local_context_->handler_num_dec();
        thread_local_context_->enable_perf_sampling_event(threadState[threadtid]);
        return;
    }

    if (thread_local_context_->get_breakpoint_fd() != info->si_fd)
    {
        //ERROR("breakpoint hit with wrong fd:%d(expected %d) %d", info->si_fd, thread_local_context.get_breakpoint_fd(),thread_local_context.get_tid());
        not_reset_entry(ucontext);
        thread_local_context_->enable_perf_sampling_event(threadState[threadtid]);
        thread_local_context_->handler_num_dec();
        return;
    }
    ucontext_t *uc = (ucontext_t *)ucontext;
    uint64_t pc = get_pc(uc);
    uint64_t bp_addr = thread_local_context_->get_breakpoint_addr();
    
    if (bp_addr != thread_local_context_->get_branch().from_addr || !executable_segments->isAddressInExecutableSegment(pc))
    {
        ERROR("real breakpoint %#lx is different from setted breakpoint addr %#lx %d ", pc, bp_addr, threadtid);
       
        thread_local_context_->handler_num_dec();
        not_reset_entry(ucontext);
        thread_local_context_->enable_perf_sampling_event(threadState[threadtid]);
        return;
    }
    
    auto [target, taken] = check_branch_if_taken(*thread_local_context_, *uc, false);
    if(target == UNKNOWN_ADDR){
       //DEBUG("enable perf sampling event %d",thread_local_context.get_tid());
       //ERROR("check_branch error\n ");
       not_reset_entry(ucontext);
       thread_local_context_->enable_perf_sampling_event(threadState[threadtid]);
       thread_local_context_->handler_num_dec();
       return;
    }

    if (pc != bp_addr) {
        WARNING("tid %d: pc #%lx is different form bp_addr %#lx, pc is , bp_ad", threadtid, pc, bp_addr);
        if (target != pc && target != pc + 4) {
          WARNING("tid %d: os or hardware is something wrong and we just restart. target is %#lx", threadtid, target);
          thread_local_context_->handler_num_dec();
          not_reset_entry(ucontext);
          thread_local_context_->enable_perf_sampling_event(threadState[threadtid]);
          return;
        }
        WARNING("tid %d: os or hardware is something wrong but we can avoid it, target is %#lx", threadtid, target);
    }

    if (taken)
    {
        if(!thread_local_context_->stack_lbr_entry_full()){
            thread_local_context_->set_to_addr(target);
            thread_local_context_->add_to_stack_lbr_entry();
        }
        if (thread_local_context_->stack_lbr_entry_full())
        {
            //WARNING("call stack sample check point %d ",thread_local_context.get_tid());

            thread_local_context_->reset_unwind();
            uint8_t real_frame_size = 0;
            if (!thread_local_context_->unwind(ucontext, thread_local_context_->get_entry()->get_stack_buffer(), MAX_FRAME_SIZE, real_frame_size,thread_local_context_->get_tid(),executable_segments));
            {
                ERROR("fail to get the call stack");
            }
            //WARNING("successfully unwind %d",thread_local_context.get_tid() );
            thread_local_context_->get_entry()->set_stack_size(real_frame_size);
            thread_local_context_->reset();//
            thread_local_context_->enable_perf_sampling_event(threadState[threadtid]);
            thread_local_context_->handler_num_dec();
            return;
        }
        
    }
    if (breakpointNum[threadtid] >= MAX_BREAKPOINT_NUM) {
        thread_local_context_->handler_num_dec();
        return;
    }
    breakpointNum[threadtid]++;
    bool ok = find_next_unresolved_branch(*thread_local_context_, uc, target);
    uint64_t next_from_addr = thread_local_context_->get_branch().from_addr;
    if (!executable_segments->isAddressInExecutableSegment(next_from_addr))
    {
        //ERROR("breakpoint handler triggered at un-executable pc %lx tid is %d", next_from_addr,thread_local_context_->get_tid());
        not_reset_entry(ucontext);
        thread_local_context_->enable_perf_sampling_event(threadState[threadtid]);
        thread_local_context_->handler_num_dec();
        return;
    }

    if (ok) {
        thread_local_context_->change_perf_breakpoint_event(next_from_addr, threadState[threadtid]);
        thread_local_context_->enable_perf_breakpoint_event(threadState[threadtid]);
    } else {
        thread_local_context_->enable_perf_sampling_event(threadState[threadtid]);
    }
    thread_local_context_->handler_num_dec();
    return;
}

void sampling_handler(int signum, siginfo_t *info, void *ucontext)
{
    threadtid = syscall(SYS_gettid);
    for (int i = 0; i < MAX_THREAD_NUM; i++) {
        if (thread_context[i].get_tid() == threadtid) {
            INFO("%d get thread local context", threadtid);
            thread_local_context_ = &thread_context[i];
            break;
        }
    }
    if (mainThread.load() & sendstop) {
        thread_local_context_->disable_perf_sampling_event(threadState[threadtid]);
        return;
    }
    if (info == nullptr || ucontext == nullptr) {
        INFO("sampling_handler info or ucontext is nullptr");
        return;
    }
    thread_local_context_->handler_num_inc();
    if (mainThread.load() & sendstop) {
        thread_local_context_->disable_perf_sampling_event(threadState[threadtid]);
        thread_local_context_->handler_num_dec();
        return;
    }
    sampleNum[threadtid]++;
    thread_local_context_->disable_perf_sampling_event(threadState[threadtid]);
    // SignalGuard signal_guard;
    /**
     * preconditions:
     * 1. thread is in sampling mode
     * 2. fd triggering event is sampling_fd_
      */
    if (!thread_local_context_->is_sampling())
    {
        //INFO1("sampling_handler redudant ");
        //ERROR("redudant sampling handler(probably from previous fd), just return %d",thread_local_context_->get_tid());
        thread_local_context_->handler_num_dec();
        return;
    }

    if (thread_local_context_->get_sampling_fd() != info->si_fd)
    {
        //ERROR("sampling hit with wrong fd:%d(expected %d) %d ", info->si_fd, thread_local_context_->get_sampling_fd() ,thread_local_context_->get_tid());
        thread_local_context_->handler_num_dec();
        return;
    }
    not_reset_entry(ucontext);
    
    ucontext_t *uc = (ucontext_t *)ucontext;

    // get PC
    uint64_t pc = get_pc(uc);
    DEBUG("tid %d: sampling_handler get_pc %#lx",threadtid, pc);

    if (!executable_segments->isAddressInExecutableSegment(pc))
    {
        ERROR("tid %d: Sampling handler triggered at un-executable pc %lx", threadtid, pc);
        thread_local_context_->enable_perf_sampling_event(threadState[threadtid]);
        thread_local_context_->handler_num_dec();
        return;
    }

    bool ok = find_next_unresolved_branch(*thread_local_context_, uc, pc);
    if (ok) {
        thread_local_context_->change_perf_breakpoint_event(thread_local_context_->get_branch().from_addr, threadState[threadtid]);
        if (thread_local_context_->get_breakpoint_fd() == -1) {
          WARNING("tid %d: bp_fd == -1 so need to enable perf sampling_event()");
          thread_local_context_->enable_perf_sampling_event(threadState[threadtid]);
          thread_local_context_->handler_num_dec();
          return;
        }
        thread_local_context_->enable_perf_breakpoint_event(threadState[threadtid]);
    } else {
        thread_local_context_->enable_perf_sampling_event(threadState[threadtid]);
    }
    thread_local_context_->handler_num_dec();
}

void start_profiler(pid_t pid)
{
    for (pid_t bufferPid : buffer_manager->tidsVector)
    {
        buffer_manager->bufferMap[bufferPid] = std::make_shared<StackLBRBuffer>();
        breakpointNum[bufferPid] = 0;
        if (buffer_manager->bufferMap[bufferPid] == nullptr) {
            threadState[bufferPid] = bufferNull;
        } else {
            threadState[bufferPid] = buffer;
        }
    }
    for (int i = 0; i < buffer_manager->tidsVector.size(); i++) {
        pid_t tid = buffer_manager->tidsVector[i];
        if (threadState[tid] & buffer) {
            thread_context[i].set_tid(tid);
            thread_context[i].thread_context_init();
            thread_context[i].breakpointNum = 0;
            thread_context[i].set_buffer_manager(buffer_manager);
            sampleNum[tid] = 0;
            threadNum[tid] = 0;
            threadState[tid] = threadState[tid] | context;
        }
    }
    for (int i = 0; i < buffer_manager->tidsVector.size(); i++) {
        pid_t tid = buffer_manager->tidsVector[i];
        if (threadState[tid] & context) {
            thread_context[i].open_perf_sampling_event(threadState[tid]);
            thread_context[i].init_perf_breakpoint_event(threadState[tid]);
        }
    }
    return;
}

void stop_profiler(pid_t pid)
{

    for (int i = 0; i < buffer_manager->tidsVector.size(); i++) {
        pid_t tid = buffer_manager->tidsVector[i];
        if (threadState[tid] & context) {
            thread_context[i].thread_stop();
            thread_context[i].breakpointNum = 0;
            while (thread_context[i].get_handler_num() != 0) //
            {
            	// Yield CPU to other threads to avoid busy polling while waiting for handlers to complete
            	std::this_thread::yield();
            }
        }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    for (int i = 0; i < buffer_manager->tidsVector.size(); i++) {
        pid_t tid = buffer_manager->tidsVector[i];
        if (threadState[tid] & context) {
            thread_context[i].thread_context_destroy();
        }
    }
}

/* main thread is designed to :
 * 1. spawn writer thread for writing output file
 * 2. periodically call start_profiler and stop_profiler
 */

void update_pid() {
    pid_t pid = getpid();
    INFO("update pid %d" , pid);
    preload_main();
}

void profiler_main_thread()
{ 
    pid_t pid = getpid();
    pid_t tid = syscall(SYS_gettid);
    pthread_atfork(NULL, NULL, update_pid);
    std::this_thread::sleep_for(std::chrono::milliseconds(30000));
    get_mmap(pid);
    print_mmap(pid, buffer_manager->output_file);
    print_buildids(buffer_manager->buildid_file);
    int i = 0;
    while (i++ < 1000000)
    { 
        if (!buffer_manager->tidsVector.empty()) {
            INFO("tidsVector is not empty");
        }
        if (!buffer_manager->bufferMap.empty()) {
            INFO("bufferMap is not empty");
        }
        if (!threadState.empty()) {
            INFO("threadState is not empty");
        }
        buffer_manager->tidsVector = get_tids(pid, std::vector<pid_t>{tid}, MAX_THREAD_NUM);
        mainThread = mainstart;
        start_profiler(pid);
        std::this_thread::sleep_for(std::chrono::milliseconds(SOFTLBR_TIEM));
        mainThread = mainThread | sendstop;
        stop_profiler(pid);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        for (const auto& pair : buffer_manager->bufferMap) {
            if (pair.second != nullptr) {
                pair.second->output(buffer_manager->output_file);
            } else {
                INFO("tip = %d buf is nullptr", pair.first);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        buffer_manager->bufferMap.clear();
        buffer_manager->tidsVector.clear();
        threadState.clear();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        while(!threadState.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            threadState.clear();
        }
    }
    delete buffer_manager;
    return;
}

__attribute__((constructor)) void preload_main()
{
    initLogFile();
    executable_segments = new ExecutableSegments(true);
    buffer_manager = new BufferManager(MAX_THREAD_NUM, "perf_data.br", "buildid-list.txt"); 
    // register handler of SIGIO for all threads
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_sigaction = sampling_handler;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigfillset(&sa.sa_mask);
        if (sigaction(SIGRTMIN+3, &sa, NULL) != 0)
        {
            perror("sigaction");
            return;
        }
    }

    // register handler of SIGTRAP for all threads
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_sigaction = breakpoint_handler;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigfillset(&sa.sa_mask);
        if (sigaction(SIGRTMIN+4, &sa, NULL) != 0)
        {
            perror("sigaction");
            return;
        }
    }
    std::thread t(profiler_main_thread);
    t.detach();

    atexit([]()
           { 
                INFO("Just for testing :D Hooked exit function"); });
}
