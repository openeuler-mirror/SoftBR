#include "thread_context.h"
#include <fcntl.h>
#include <linux/hw_breakpoint.h>

uint64_t get_mmap_len()
{
    return sysconf(_SC_PAGESIZE) * (1 + RINGBUFFER_SIZE);
}

void ThreadContext::init_perf_breakpoint_event(int &threadState) {
    // init the file descriptor for breakpoint event
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_BREAKPOINT;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = 0;
    pe.bp_type = HW_BREAKPOINT_X;
    pe.bp_addr = (uintptr_t)(0); // use a dummy address
    pe.bp_len = 8;
    pe.sample_period = 1; // make sure every breakpoint will cause a overflow
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    assert(this->bp_fd_ == -1 && "previous breakpoint events must be closed");
    if (kill(tid_, 0) == -1) {
        ERROR("%d is dead", tid_);
        return;
    }
    if ((this->bp_fd_ = syscall(__NR_perf_event_open, &pe, tid_, -1, -1, 0)) < 0) {
        ERROR("perf_event_open");
        ERROR("no left breakpoint");
    }

    struct f_owner_ex owner = {
        .type = F_OWNER_TID,
        .pid = tid_
    };

    if (fcntl(this->bp_fd_, F_SETOWN_EX, &owner) == -1) {
        ERROR("F_SETSIG bp fd is %d tid is %d", this->bp_fd_, tid_); // error tid is -1 bp is -1
        exit(EXIT_FAILURE);
    }

    if (fcntl(this->bp_fd_, F_SETSIG, SIGRTMIN + 4) == -1) {
        ERROR("F_SETSIG bp fd is %d tid is %d", this->bp_fd_, tid_); // error tid is -1 bp is -1
        ERROR("F_SETSIG");
        exit(EXIT_FAILURE);
    }

    int flags = fcntl(this->bp_fd_, F_GETFL, 0);
    if (flags == -1) {
        ERROR("F_GETFL bp fd is %d tid is %d", this->bp_fd_, tid_); // error tid is -1 bp is -1
        ERROR("F_GETFL");
        exit(EXIT_FAILURE);
    }

    if (fcntl(this->bp_fd_, F_SETFL, flags | O_ASYNC) == -1) {
        ERROR("F_SETFL");
        exit(EXIT_FAILURE);
    }
    threadState = threadState | breakpointOpen;
    INFO("%d successfully init breakpoint with fd: %d", tid_, bp_fd_);
}

void ThreadContext::change_perf_breakpoint_event(uint64_t addr, int &threadState) {
    if (!(state_ & (thread_state::BREAKPOINT | thread_state::SAMPLING))) {
        INFO("stop profiling with state %d", state_.load());
        return;
    }

    this->state_ = thread_state::BREAKPOINT;
    this->bp_addr_ = addr;
    if (threadState & breakpointOpen) {
        //INFO("change breakpoint when not open");
    }
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.type = PERF_TYPE_BREAKPOINT;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = 0;
    pe.bp_type = HW_BREAKPOINT_X;
    pe.bp_addr = (uintptr_t)(addr);
    pe.bp_len = 8;
    pe.sample_period = 1; // make sure every breakpoint will cause a overflow
    pe.disabled = 1;
    pe.exclude_kernel = 1;    
    DEBUG("%d successfully change breakpoint at %lx(fd: %d)", tid_, bp_addr_, bp_fd_);
    // directly update the breakpoint attributes
    if (ioctl(this->bp_fd_, PERF_EVENT_IOC_MODIFY_ATTRIBUTES, &pe) != 0) {
        WARNING("PERF_EVENT_IOC_MODIFY_ATTRIBUTES fails %d", errno);
        return;
    }
    // test to see if the following resetting is necessary
    if (ioctl(this->bp_fd_, PERF_EVENT_IOC_RESET, 0) != 0) {
        WARNING("reset failure %d", tid_);
        WARNING("PERF_EVENT_IOC_RESET");
        return;
    }
    threadState = threadState | breakpointChange;
    DEBUG("%d with bp addr:%lx", tid_, bp_addr_);
}

void ThreadContext::open_perf_sampling_event(int &threadState)
{
    if (threadState != (context | buffer)) {
        INFO("ThreadContext 1");
        return;
    }
    errno = 0;
    this->state_ = thread_state::SAMPLING;
    /**
     * precondition: open_perf_sampling_event should be called only once
     */
    if (this->sampling_fd_ != -1)
    {
        ERROR("open_perf_sampling_event is called multiple times %d", tid_);//signal siganl
        return;
    }

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.size = sizeof(struct perf_event_attr);
    pe.type = PERF_TYPE_HARDWARE;
    pe.config = PERF_COUNT_HW_INSTRUCTIONS;
    pe.sample_period = sampling_period;
    pe.disabled = 1;
    pe.mmap = 1; // it seems that the sampling mode is only enabled combined with mmap
    pe.sample_type = PERF_SAMPLE_IP;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    this->sampling_fd_ = syscall(__NR_perf_event_open, &pe, tid_, -1, -1, 0);
    if (this->sampling_fd_ < 0)
    {
        WARNING("the perf_fd is %d", this->sampling_fd_);
        perror("here :perf_event_open");
        return;
    }
    if (threadState & sampled) {
        threadState = threadState ^ sampled;
    }
    threadState = threadState | sampleOpen;
    if (fcntl(this->sampling_fd_, F_SETFL, O_RDWR | O_NONBLOCK | O_ASYNC) != 0)
    {
        perror("F_SETFL");
        exit(EXIT_FAILURE);
    }

    if (fcntl(this->sampling_fd_, F_SETSIG, SIGRTMIN+3) != 0)
    {
        perror("F_SETSIG");
        exit(EXIT_FAILURE);
    }

    struct f_owner_ex owner;
    owner.type = F_OWNER_TID;
    owner.pid = this->tid_;
    if (fcntl(this->sampling_fd_, F_SETOWN_EX, &owner) != 0)
    {
        perror("F_SETOWN_EX");
        exit(EXIT_FAILURE);
    } 
    DEBUG("successfully sampling with  %d %d",this->sampling_fd_,tid_);
    if (ioctl(this->sampling_fd_, PERF_EVENT_IOC_RESET, 0) != 0)
    {
        
        perror("PERF_EVENT_IOC_RESET");
        exit(EXIT_FAILURE);
    }

    if (ioctl(this->sampling_fd_, PERF_EVENT_IOC_ENABLE, 0) != 0)
    {
        perror("PERF_EVENT_IOC_ENABLE");
        exit(EXIT_FAILURE);
    }
    threadState = threadState | sampling;
    threadNum[tid_]++;
    WARNING("exit perf_events open with errno %d", errno);
    if (errno)
    {
        ERROR("fail in perf_events enable");
    }
}

bool ThreadContext::stack_lbr_entry_full()
{
    return thread_stack_lbr_entry_.is_full();
}

void ThreadContext::stack_lbr_entry_reset()
{
    DEBUG("begin to reset the lbr entry of thread %d", tid_);
    if (thread_buffer_ == nullptr)
    {
        WARNING("thread %d get null thread buffer", tid_);
       
    }
    else if (thread_stack_lbr_entry_.get_stack_size() && false == thread_stack_lbr_entry_.serialize(thread_buffer_->get_current(), thread_buffer_->get_buffer_size()))
    {
        return;
    }
    
     if (thread_stack_lbr_entry_.get_stack_size() == 0) {
        INFO("%d fails to push an entry", tid_);
    } else {
        branch_dyn_cnt_ += thread_stack_lbr_entry_.get_branch_size();
    }

    thread_stack_lbr_entry_.reset();
    DEBUG("succeed to reset the lbr entry of thread %d", tid_);
}

void ThreadContext::add_to_stack_lbr_entry()
{
    thread_stack_lbr_entry_.add_branch(cur_branch_.from_addr, cur_branch_.to_addr);
}