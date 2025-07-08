#ifndef LBR_UTILS
#define LBR_UTILS
#include "consts.h"
#include "decoder.hpp"
#include "log.h"
#include "thread_context.h"
#include <asm/unistd.h>
#include <fcntl.h>
#include <iostream>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>

struct mmap_info {
    uint64_t addr;
    uint64_t len;
    uint64_t pgoff;
    uint32_t maj;
    uint32_t min;
    uint64_t ino;
    uint64_t ino_generation;
    uint32_t prot;
    uint32_t flags;
    std::string filename;
};

struct build_id {
    unsigned char data[20];
    int size;
};

void get_mmap(pid_t pid);

void print_mmap(pid_t pid, std::ostream &os);

mmap_info parseMapsLine(const std::string& line, pid_t pid);

void print_buildids(std::ostream &os);

typedef struct user_regs_struct user_context;

uint64_t get_pc(ucontext_t *ucontext);

long perf_event_open(struct perf_event_attr *event_attr, pid_t pid, int cpu,
                     int group_fd, unsigned long flags);

bool find_next_branch(ThreadContext &tcontext, ucontext_t *uc, uint64_t pc, int length);

void init_dr_mcontext(dr_mcontext_t *mcontext, ucontext_t *ucontext);

std::pair<uint64_t, bool> check_branch_if_taken(ThreadContext &tcontext, ucontext_t &context, bool static_eval);

std::vector<pid_t> get_tids(pid_t target_pid, const std::vector<pid_t>& exclue_targets, std::size_t max_size);

// return [target_addr, should make breakpoint]
std::pair<uint64_t, bool> static_evaluate(ThreadContext &tcontext, uint64_t pc, instr_t *d_insn);

// return [target_addr, taken]
std::pair<uint64_t, bool> evaluate(ThreadContext &tcontext, void *dr_context, instr_t *d_insn, ucontext_t *ucontext);

std::pair<uint64_t, bool> evaluate_x86(void *dr_context_, instr_t *d_insn, ucontext_t *ucontext);

std::pair<uint64_t, bool> evaluate_arm(ThreadContext &tcontext, void *dr_context_, instr_t *d_insn, ucontext_t *ucontext);

void print_backtrace();

int tgkill(pid_t group_id, pid_t tid, int signo);
#endif