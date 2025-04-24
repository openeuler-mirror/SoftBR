#include "utils.h"
#include "dr_api.h"
#include "dr_ir_decode.h"
#include "dr_ir_instr.h"
#include "dr_tools.h"
#include <algorithm>
#include <random>
#include <cassert>
#include <cstring>
#include <ctype.h>
#include <dirent.h>
#include <libunwind-ptrace.h>
#include <libunwind.h>
#include <linux/hw_breakpoint.h>
#include <string>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unordered_set>

#if defined(__x86_64__)
#include <libunwind-x86_64.h>
#elif defined(__aarch64__)
#include <libunwind-aarch64.h>
#endif

#define X86

long perf_event_open(struct perf_event_attr *event_attr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
  return syscall(__NR_perf_event_open, event_attr, pid, cpu, group_fd, flags);
}

uint64_t get_pc(ucontext_t *ucontext)
{
#if defined(__x86_64__)
  return (uint64_t)(ucontext->uc_mcontext.gregs[REG_RIP]);
#elif defined(__aarch64__)
  return (uint64_t)(ucontext->uc_mcontext.pc);
#endif
}

bool find_next_branch(ThreadContext &tcontext, ucontext_t *uc, uint64_t pc, int length)
{
  dr_mcontext_t mcontext;
  void *dr_context = dr_get_current_drcontext();
  init_dr_mcontext(&mcontext, uc);

  instr_noalloc_t noalloc;
  instr_noalloc_init(dr_context, &noalloc);
  instr_t *d_insn = instr_from_noalloc(&noalloc);
  byte *addr = (byte *)(pc);

  INFO("thread id %d branch is %#lx\n", tcontext.get_tid(), addr);
  while (decode(dr_context, addr, d_insn))
  {
    uint64_t temp_pc = (uint64_t)addr;

    addr += 4;

    if (!instr_is_cti(d_insn))
      continue;

    if (instr_is_syscall(d_insn)) 
    {
      INFO("encounter a unexpected syscall!");
      return false;
    }

    // find a branch and fill in its from address
    tcontext.set_from_addr(temp_pc);
    return true;
  }

  return false;
}

void enable_perf_sampling(pid_t tid, int perf_fd)
{
  DEBUG("enable perf sampling for %d", tid);
  if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) == -1)
  {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    exit(EXIT_FAILURE);
  }
}

std::pair<uint64_t, bool> check_branch_if_taken(ThreadContext &tcontext, ucontext_t &context, bool static_eval)
{

  uint64_t from_addr = tcontext.get_branch().from_addr;
  dr_mcontext_t mcontext;
	void *dr_context = tcontext.get_dr_context();
	init_dr_mcontext(&mcontext, &context);

	instr_noalloc_t noalloc;
	instr_noalloc_init(dr_context, &noalloc);
	instr_t *d_insn = instr_from_noalloc(&noalloc);
	byte *addr = (byte *)from_addr;

  if (decode(dr_context, addr, d_insn)) {
    if (!instr_is_cti(d_insn)) {
      ERROR("Expected control-flow transfer instruction at %#lx", from_addr);
			return std::make_pair(0, false);
    }


    auto [target, taken] = static_eval ? static_evaluate(tcontext, from_addr, d_insn) : evaluate(tcontext, dr_context, d_insn, &context);
    if (taken)
    {
      if (static_eval)
      {
        tcontext.add_static_branch();
      }
      else
      {
        tcontext.add_dynamic_branch();
      }
    }

    return std::make_pair(target, taken);
  }
  else
  {
    ERROR("check_branch_if_taken: fail to decode the cti");
  }

  return std::make_pair(0, false);

  }

std::string parseMapsLine(const std::string& line, pid_t pid) {
  std::istringstream iss(line);

  std::string address_range, permissions, offset, device, inode, pathname;

  iss >> address_range >> permissions >> offset >> device >> inode >> pathname;

  if (permissions != "r-xp") {
    return "";
  }

  size_t dash_pos = address_range.find('-');
  std::string start_address = address_range.substr(0, dash_pos);
  std::string end_address = address_range.substr(dash_pos + 1);

  unsigned long start_addr = std::stoul(start_address, nullptr, 16);
  unsigned long end_addr = std::stoul(end_address, nullptr, 16);
  unsigned long size = end_addr - start_addr;

  size_t colon_pos = device.find(':');
  std::string major = device.substr(0, colon_pos);
  std::string minor = device.substr(colon_pos + 1);

  unsigned long offset_value = std::stoul(offset, nullptr, 16);
  std::string offset_string;

  if (offset_value == 0) {
    offset_string = "0";
  } else {
    std::ostringstream oss;
    oss << "0x" << std::hex << offset_value;
    offset_string = oss.str();
  }

  std::ostringstream oss;

  oss << "PERF_RECORD_MMAP2 " << pid << "/" << pid << ": "
      << "[0x" << start_address << "(0x" <<  std::hex << size << ") @ " << offset_string << " "
      << major << ":" << minor << " " << inode << " 0]: " << permissions << " " << pathname;

  return oss.str();
}

void get_mmap(pid_t pid, std::ostream &os) {
  std::string path_maps = "/proc/" + std::to_string(pid) + "/maps";
  std::ifstream file_maps(path_maps);

  if (!file_maps.is_open()) {
    std::cerr << "can not read file: " << path_maps << std::endl;
    return; 
  }

  std::string line;

  while (std::getline(file_maps, line))
  {
    std::string perf_record = parseMapsLine(line, pid);
    if (perf_record.empty()) {
      continue;
    }
    os << perf_record << std::endl;
  }
  file_maps.close();
}

std::vector<pid_t> get_tids(pid_t target_pid, const std::vector<pid_t>& exclue_targets, std::size_t max_size)
{
  std::vector<pid_t> tids;
  std::unordered_set<pid_t> tids_set;
  while (true)
  {
    std::string path_cpp = "/proc/" + std::to_string(target_pid) + "/task";
    //std::string path_cpp = "/proc/self/task";
    char *path = new char[path_cpp.length() + 1];
    strcpy(path, path_cpp.c_str());

    struct dirent *entry;
    DIR *dir = opendir(path);
    if (dir == NULL)
    {
      exit(-1);
    }

    bool has_new_tid = false;
    while ((entry = readdir(dir)) != NULL)
    {
      std::string tid(entry->d_name);
      if (std::all_of(tid.begin(), tid.end(), isdigit))
      {
        pid_t tid_number = std::atol(tid.c_str());

        if (std::any_of(exclue_targets.begin(), exclue_targets.end(), [&](pid_t id) {
          return id == tid_number;
        }))
          continue;

        if (tids_set.find(tid_number) == tids_set.end())
        {
          tids.push_back((pid_t)tid_number);
          tids_set.insert(tid_number);
          has_new_tid = true;
        }
      }
    }
    closedir(dir);
    if (!has_new_tid && tids.size() > 0)
      break;
    delete []path;
  }
    std::random_device rd;
    std::mt19937 g(rd());

    std::shuffle(tids.begin(),tids.end(),g);
    int real_size = std::min(tids.size(),max_size);
    std::vector<pid_t> real_tids(tids.begin(),tids.begin()+real_size);

  std::string log_str = "get_tids: Find tids:";
  for (auto &tid : tids)
  {
    log_str += std::to_string(tid) + " ";
  }

  INFO("%s", log_str.c_str());
  return real_tids;
}

void init_dr_mcontext(dr_mcontext_t *mcontext, ucontext_t *ucontext)
{
  mcontext->size = sizeof(dr_mcontext_t);
  mcontext->flags = DR_MC_ALL;

#if defined(__x86_64__)
  mcontext->xdi = ucontext->uc_mcontext.gregs[REG_RDI];
  mcontext->xsi = ucontext->uc_mcontext.gregs[REG_RSI];
  mcontext->xbp = ucontext->uc_mcontext.gregs[REG_RBP];
  mcontext->xsp = ucontext->uc_mcontext.gregs[REG_RSP];
  mcontext->xax = ucontext->uc_mcontext.gregs[REG_RAX];
  mcontext->xbx = ucontext->uc_mcontext.gregs[REG_RBX];
  mcontext->xcx = ucontext->uc_mcontext.gregs[REG_RCX];
  mcontext->xdx = ucontext->uc_mcontext.gregs[REG_RDX];
  mcontext->xip = (byte *)ucontext->uc_mcontext.gregs[REG_RIP];
  mcontext->xflags = ucontext->uc_mcontext.gregs[REG_EFL];
#elif defined(__aarch64__)
  mcontext->r0 = ucontext->uc_mcontext.regs[0];
  mcontext->r1 = ucontext->uc_mcontext.regs[1];
  mcontext->r2 = ucontext->uc_mcontext.regs[2];
  mcontext->r3 = ucontext->uc_mcontext.regs[3];
  mcontext->r4 = ucontext->uc_mcontext.regs[4];
  mcontext->r5 = ucontext->uc_mcontext.regs[5];
  mcontext->r6 = ucontext->uc_mcontext.regs[6];
  mcontext->r7 = ucontext->uc_mcontext.regs[7];
  mcontext->r8 = ucontext->uc_mcontext.regs[8];
  mcontext->r9 = ucontext->uc_mcontext.regs[9];
  mcontext->r10 = ucontext->uc_mcontext.regs[10];
  mcontext->r11 = ucontext->uc_mcontext.regs[11];
  mcontext->r12 = ucontext->uc_mcontext.regs[12];
  mcontext->r13 = ucontext->uc_mcontext.regs[13];
  mcontext->r14 = ucontext->uc_mcontext.regs[14];
  mcontext->r15 = ucontext->uc_mcontext.regs[15];
  mcontext->r16 = ucontext->uc_mcontext.regs[16];
  mcontext->r17 = ucontext->uc_mcontext.regs[17];
  mcontext->r18 = ucontext->uc_mcontext.regs[18];
  mcontext->r19 = ucontext->uc_mcontext.regs[19];
  mcontext->r20 = ucontext->uc_mcontext.regs[20];
  mcontext->r21 = ucontext->uc_mcontext.regs[21];
  mcontext->r22 = ucontext->uc_mcontext.regs[22];
  mcontext->r23 = ucontext->uc_mcontext.regs[23];
  mcontext->r24 = ucontext->uc_mcontext.regs[24];
  mcontext->r25 = ucontext->uc_mcontext.regs[25];
  mcontext->r26 = ucontext->uc_mcontext.regs[26];
  mcontext->r27 = ucontext->uc_mcontext.regs[27];
  mcontext->r28 = ucontext->uc_mcontext.regs[28];
  mcontext->r29 = ucontext->uc_mcontext.regs[29];
  mcontext->r30 = ucontext->uc_mcontext.regs[30];
  mcontext->r31 = ucontext->uc_mcontext.regs[31];
  mcontext->pc = (byte *)ucontext->uc_mcontext.pc;
  mcontext->xflags = ucontext->uc_mcontext.pstate;
#endif
}

std::pair<uint64_t, bool> static_evaluate(ThreadContext &tcontext, uint64_t pc, instr_t *d_insn) {
	// TODO: enable static when necessary
	return std::make_pair(UNKNOWN_ADDR, true);
#ifdef NO_STATIC
	return std::make_pair(UNKNOWN_ADDR, true);
#endif
	assert(d_insn && "d_insn should not be null");
	assert(instr_is_cti(d_insn) && "instruction should be a control-flow transfer instruction.");

	if (instr_is_ubr(d_insn) || instr_is_call(d_insn)) {
		opnd_t target_op = instr_get_target(d_insn);
		uint64_t target_addr = UNKNOWN_ADDR;

		if (opnd_is_immed(target_op)) {
			if (opnd_is_immed_int(target_op)) {
				target_addr = opnd_get_immed_int(target_op);
			} else if (opnd_is_immed_int64(target_op)) {
				target_addr = opnd_get_immed_int64(target_op);
			} else {
				assert(0 && "direct control flow transfer should only go to int address!");
			}
			INFO("statically evaluated address from immed: %#lx", target_addr);
		} else if (opnd_is_abs_addr(target_op)) {
			target_addr = (uint64_t)opnd_compute_address(target_op, nullptr);
			if (target_addr == 0) {
				ERROR("fail to compute the addr");
			}
			INFO("statically evaluated address from abs_addr: %#lx", target_addr);
		} else if (opnd_is_pc(target_op)) {
			target_addr = (uint64_t)opnd_get_pc(target_op);
			if (target_addr == 0) {
				ERROR("fail to compute the addr");
			}
			INFO("statically evaluated address from pc: %#lx", target_addr);
		} else {
			DEBUG("static_evaluate: the target is not imm");
		}

		if (target_addr != UNKNOWN_ADDR) {
			INFO("taken branch(static): %#lx -> %#lx", pc, target_addr);
		}
		return std::make_pair(target_addr, target_addr != UNKNOWN_ADDR);
	} else {
		return std::make_pair(UNKNOWN_ADDR, false);
	}
}

std::pair<uint64_t, bool> evaluate(ThreadContext &tcontext, void *dr_context, instr_t *d_insn, ucontext_t *ucontext)
{
#if defined(__x86_64__)
  return evaluate_x86(dr_context, context, insn, ucontext);
#elif defined(__aarch64__)
  return evaluate_arm(tcontext, dr_context, d_insn, ucontext);
#endif
}

std::pair<uint64_t, bool> evaluate_x86(void *dr_context_, instr_t *d_insn, ucontext_t *ucontext) {
  #if defined(__x86_64__)
    dr_mcontext_t mcontext;
    void *dr_context = dr_get_current_drcontext();
    init_dr_mcontext(&mcontext, ucontext);
    instr_noalloc_t noalloc;
    instr_noalloc_init(dr_context, &noalloc);
  
    // dr_print_instr(dr_context, STDOUT, d_insn, "DR-instrcution: ");
  
    // judge what kind of the instruction is and get target address
    uint64_t target_addr = UNKNOWN_ADDR;
    opnd_t target_op = instr_get_target(d_insn);
    // dr_print_opnd(dr_context, STDOUT, target_op, "DR-opnd: ");
    if (instr_is_cbr(d_insn)) {
      if (opnd_is_near_pc(target_op)) {
        INFO("evaluate_x86: cbr is pc");
        target_addr = (ptr_uint_t)opnd_get_pc(target_op);
      } else if (opnd_is_near_instr(target_op)) {
        INFO("evaluate_x86: cbr is instr");
        instr_t *tgt = opnd_get_instr(target_op);
        target_addr = (ptr_uint_t)instr_get_app_pc(tgt);
        assert(target_addr != 0 && "dr_insert_cbr_instrumentation: unknown target");
      } else {
        assert(false && "dr_insert_cbr_instrumentation: unknown target");
        target_addr = 0;
      }
    } else if (instr_is_mbr(d_insn)) {
      if (instr_is_return(d_insn)) {
        // for return, the return address is the last operand
        target_op = instr_get_src(d_insn, instr_num_srcs(d_insn) - 1);
      }
      if (opnd_is_near_pc(target_op)) {
        INFO("evaluate_x86: {return,call,jmp} is pc");
        target_addr = (ptr_uint_t)opnd_get_pc(target_op);
        // } else if (opnd_is_near_instr(target_op)) {
      } else if (opnd_is_near_instr(target_op)) {
        INFO("evaluate_x86: {return,call,jmp} is instr");
        instr_t *tgt = opnd_get_instr(target_op);
        target_addr = (ptr_uint_t)instr_get_app_pc(tgt);
        assert(target_addr != 0 && "dr_insert_cbr_instrumentation: unknown target");
      } else if (opnd_is_memory_reference(target_op)) {
        INFO("evaluate_x86: {return,call,jmp} is memory ref");
        app_pc temp_addr = opnd_compute_address(target_op, &mcontext);
        if (temp_addr == nullptr) {
          ERROR("fail to compute the address of operand");
        }
        // Dereference temp_addr to get the actual target address stored at that memory location
        target_addr = *(uint64_t *)(temp_addr);
        // target_addr = (uint64_t)(temp_addr);
      } else if (opnd_is_reg(target_op)) {
        INFO("evaluate_x86: {return,call,jmp} is reg");
        target_addr = reg_get_value(opnd_get_reg(target_op), &mcontext);
      } else {
        assert(false && "dr_insert_cbr_instrumentation: unknown target");
        target_addr = 0;
      }
    } else if (instr_is_call(d_insn) || instr_is_ubr(d_insn)) {
      // For call instructions, return address is next instruction
      if (opnd_is_pc(target_op)) {
        INFO("evaluate_x86: {call,ubr} is pc");
  
        if (opnd_is_far_pc(target_op)) {
          /* FIXME: handle far pc */
          assert(false && "dr_insert_{ubr,call}_instrumentation: far pc not supported");
        }
  
        target_addr = (ptr_uint_t)opnd_get_pc(target_op);
      } else if (opnd_is_instr(target_op)) {
        INFO("evaluate_x86: {call,ubr} is instr");
  
        // Get the target instruction
        instr_t *tgt = opnd_get_instr(target_op);
  
        // Instead of using translation field directly, get the PC from the instruction
        target_addr = (ptr_uint_t)instr_get_app_pc(tgt);
        if (target_addr == 0) {
          // Fallback to getting raw bits if app PC not available
          target_addr = (ptr_uint_t)instr_get_raw_bits(tgt);
        }
  
        assert(target_addr != 0 && "dr_insert_{ubr,call}_instrumentation: unknown target");
  
        if (opnd_is_far_instr(target_op)) {
          /* FIXME: handle far instr */
          assert(false && "dr_insert_{ubr,call}_instrumentation: far instr "
                          "not supported");
        }
      } else {
        assert(false && "dr_insert_{ubr,call}_instrumentation: unknown target");
        target_addr = 0;
      }
    } else {
      assert(0 && "fail to decode such a branch");
    }
  
    if (target_addr == UNKNOWN_ADDR) {
      puts("fail to get the target address of the operand");
      exit(EXIT_FAILURE);
    } else {
      DEBUG("the target address of the current instruction is %#lx", target_addr);
    }
  
    bool taken = true;
    if (instr_is_cbr(d_insn)) {
      DEBUG("begin to eval cbr");
      uint32_t eflags = mcontext.xflags;
  
      switch (instr_get_opcode(d_insn)) {
      case OP_jb:
      case OP_jb_short:
        taken = mcontext.xflags & EFLAGS_CF; // CF=1
        break;
      case OP_jbe:
      case OP_jbe_short:
        taken = (mcontext.xflags & EFLAGS_CF) || (mcontext.xflags & EFLAGS_ZF); // CF=1 or ZF=1
        break;
      case OP_jecxz:
        taken = mcontext.xcx & 0xFFFFFFFF;
        break;
      case OP_jl:
      case OP_jl_short:
        taken = (mcontext.xflags & EFLAGS_SF) != (mcontext.xflags & EFLAGS_OF); // SF!=OF
        break;
      case OP_jle:
      case OP_jle_short:
        taken = (mcontext.xflags & EFLAGS_ZF) ||
                ((mcontext.xflags & EFLAGS_SF) != (mcontext.xflags & EFLAGS_OF)); // ZF=1 | SF!=OF
        break;
      case OP_jnb:
      case OP_jnb_short:
        taken = !(mcontext.xflags & EFLAGS_CF); // CF=0
        break;
      case OP_jnbe:
      case OP_jnbe_short:
        taken = !(mcontext.xflags & EFLAGS_CF) && !(mcontext.xflags & EFLAGS_ZF); // CF=0 and ZF=0
        break;
      case OP_jnl:
      case OP_jnl_short:
        taken = (mcontext.xflags & EFLAGS_SF) == (mcontext.xflags & EFLAGS_OF); // SF=OF
        break;
      case OP_jnle:
      case OP_jnle_short:
        taken = (mcontext.xflags & EFLAGS_ZF) &&
                ((mcontext.xflags & EFLAGS_SF) == (mcontext.xflags & EFLAGS_OF)); // ZF=1 and SF=OF
        break;
      case OP_jno:
      case OP_jno_short:
        taken = !(mcontext.xflags & EFLAGS_OF); // OF=0
        break;
      case OP_jnp:
      case OP_jnp_short:
        taken = !(mcontext.xflags & EFLAGS_PF); // PF=0
        break;
      case OP_jns:
      case OP_jns_short:
        taken = !(mcontext.xflags & EFLAGS_SF); // SF=0
        break;
      case OP_jnz:
      case OP_jnz_short:
        taken = !(mcontext.xflags & EFLAGS_ZF); // ZF=0
        break;
      case OP_jo:
      case OP_jo_short:
        taken = mcontext.xflags & EFLAGS_OF; // OF=1
        break;
      case OP_jp:
      case OP_jp_short:
        taken = mcontext.xflags & EFLAGS_PF; // PF=1
        break;
      case OP_js:
      case OP_js_short:
        taken = mcontext.xflags & EFLAGS_SF; // SF=1
        break;
      case OP_jz:
      case OP_jz_short:
        taken = mcontext.xflags & EFLAGS_ZF; // ZF=1
        break;
      default:
        // Handle other conditional branches as needed
        assert(0 && "unhandled jump instrcution.");
        break;
      }
  
      if (taken) {
        DEBUG("the conditional branch is taken");
      } else {
        DEBUG("the conditional branch is not taken");
      }
    } else {
      DEBUG("the unconditional branch is taken");
    }
  
    // handle the cbr
  
    if (taken) {
      INFO("taken branch: %#lx -> %#lx", get_pc(ucontext), target_addr);
    } else {
      // since not taken, target addr will be the next instruction
      target_addr = get_pc(ucontext) + instr_length(dr_context, d_insn);
      INFO("continue from %#lx", target_addr);
    }
    return std::make_pair(target_addr, taken);
  #else
    return std::make_pair(UNKNOWN_ADDR, false);
  #endif
  }
  

std::pair<uint64_t, bool> evaluate_arm(ThreadContext &tcontext, void *dr_context_, instr_t *d_insn, ucontext_t *ucontext) {
  #if defined(__aarch64__)
    assert(instr_is_cti(d_insn) && "instruction should be a control-flow transfer instruction.");
  
    dr_mcontext_t mcontext;
    void *dr_context = dr_get_current_drcontext();
    init_dr_mcontext(&mcontext, ucontext);
    instr_noalloc_t noalloc;
    uint64_t pc = get_pc(ucontext);
    byte *addr = (byte *)(get_pc(ucontext));
    if (pc != tcontext.get_breakpoint_addr()) {
      addr = (byte *)tcontext.get_breakpoint_addr();
    }
    
  
    // judge what kind of the instruction is and get target address
    uint64_t target_addr = UNKNOWN_ADDR;
    opnd_t target_op = instr_get_target(d_insn);
    // dr_print_opnd(dr_context, STDOUT, target_op, "DR-opnd: ");
    if (instr_is_cbr(d_insn)) {
      if (opnd_is_near_pc(target_op)) {
        target_addr = (ptr_uint_t)opnd_get_pc(target_op);
        DEBUG("tid %d, evaluate_arm: cbr is pc, target addr = %#lx", tcontext.get_tid(), target_addr);
      } else {
        assert(false && "dr_insert_cbr_instrumentation: unknown target");
        target_addr = 0;
      }
    } else if (instr_is_mbr(d_insn)) {
      if (instr_is_return(d_insn)) {
        // for return, the return address is the last operand
        target_op = instr_get_src(d_insn, instr_num_srcs(d_insn) - 1);
        DEBUG("tid %d, evaluate_arm: cbr is instr, target op = %#lx", tcontext.get_tid(), target_op);
      }
      if (opnd_is_reg(target_op)) {
        target_addr = reg_get_value(opnd_get_reg(target_op), &mcontext);
        DEBUG("tid %d, evaluate_arm: {ret} is memory reg, target addr = %#lx", tcontext.get_tid(), target_addr);
      } else {
        assert(false && "dr_insert_cbr_instrumentation: unknown target");
        target_addr = 0;
      }
    } else if (instr_is_call(d_insn) || instr_is_ubr(d_insn)) {
      // For call instructions, return address is next instruction
      if (opnd_is_pc(target_op)) {
        DEBUG("tid %d, evaluate_arm: instr is pc, target op = %#lx", tcontext.get_tid(), target_op);
        if (opnd_is_far_pc(target_op)) {
          /* FIXME: handle far pc */
          assert(false && "dr_insert_{b,bl}_instrumentation: far pc not supported");
        }
  
        target_addr = (ptr_uint_t)opnd_get_pc(target_op);
        DEBUG("tid %d, evaluate_arm: {b,bl} is pc, target addr = %#lx", tcontext.get_tid(), target_addr);
      } else {
        assert(false && "dr_insert_{b,bl}_instrumentation: unknown target");
        target_addr = 0;
      }
    } else {
      assert(0 && "fail to decode such a branch");
    }
  
    auto condition_holds = [](uint8_t cond, const dr_mcontext_t *mcontext) -> bool {
      assert(cond <= 0xF && "provided cond must less than 4 bits!");
  
      bool res = false;
      bool n = mcontext->xflags >> 31 & 1;
      bool z = mcontext->xflags >> 30 & 1;
      bool c = mcontext->xflags >> 29 & 1;
      bool v = mcontext->xflags >> 28 & 1;
      switch (cond >> 1) {
      case 0x0:
        res = z;
        break;
      case 0x1:
        res = c;
        break;
      case 0x2:
        res = n;
        break;
      case 0x3:
        res = v;
        break;
      case 0x4:
        res = c && !z;
        break;
      case 0x5:
        res = n == v;
        break;
      case 0x6:
        res = n == v && !z;
        break;
      case 0x7:
        res = true;
        break;
      default:
        assert(0 && "provided cond must less than 4 bits!");
      }
  
      if ((cond & 1) == 1 && cond != 0xF) {
        res = !res;
      }
  
      return res;
    };
  
    auto sign_extend = [](uint64_t origin, uint8_t bit_length) -> int64_t {
      return static_cast<int64_t>(origin) << (64 - bit_length) >> (64 - bit_length);
    };
  
    bool taken = true;
    uint32_t raw_inst = *(uint32_t *)addr;
    if (instr_is_cbr(d_insn)) {
      switch (instr_get_opcode(d_insn)) {
      case OP_b: {
        WARNING("instruction \"b\" is a static branch");
        taken = true;
        break;
      }
      case OP_bl: {
        WARNING("instruction \"bl\" is a static branch");
        taken = true;
        break;
      }
      case OP_blr: {
        taken = true;
        break;
      }
      case OP_br: {
        taken = true;
        break;
      }
      case OP_blraa:
      case OP_blraaz:
      case OP_blrab:
      case OP_blrabz: {
        WARNING("branch with pointer authentication is not fully supported");
        taken = true;
        break;
      }
      case OP_braa:
      case OP_braaz:
      case OP_brab:
      case OP_brabz: {
        WARNING("branch with pointer authentication is not fully supported");
        taken = true;
        break;
      }
      case OP_bcond: {
        uint8_t cond = raw_inst & ((1 << 4) - 1);
        int64_t imm = sign_extend((raw_inst >> 5) & ((1 << 19) - 1), 19) << 2;
  
        taken = condition_holds(cond, &mcontext);
        break;
      }
      case OP_cbnz: {
        uint8_t reg_id = raw_inst & ((1 << 5) - 1); // 修正为5位寄存器编号
  
        taken = ucontext->uc_mcontext.regs[reg_id] != 0;
        break;
      }
      case OP_cbz: {
        uint8_t reg_id = raw_inst & ((1 << 5) - 1);
  
        taken = ucontext->uc_mcontext.regs[reg_id] == 0;
        break;
      }
      case OP_tbnz: {
        uint32_t bit_pos = ((raw_inst >> 31 & 1) << 4) + (raw_inst >> 19 & ((1 << 5) - 1));
        // int64_t imm = sign_extend((raw_inst >> 5) & ((1 << 14) - 1), 14) << 2;
        uint8_t reg_id = raw_inst & ((1 << 5) - 1);
  
        taken = (ucontext->uc_mcontext.regs[reg_id] >> bit_pos & 1) != 0;
        break;
      }
      case OP_tbz: {
        uint32_t bit_pos = ((raw_inst >> 31 & 1) << 4) + (raw_inst >> 19 & ((1 << 5) - 1));
        // int64_t imm =
        sign_extend((raw_inst >> 5) & ((1 << 14) - 1), 14) << 2;
        uint8_t reg_id = raw_inst & ((1 << 5) - 1);
  
        taken = (ucontext->uc_mcontext.regs[reg_id] >> bit_pos & 1) == 0;
        break;
      }
      default:
        assert(0 && "this instruction is not a branch instruction!");
      }
    }
    // handle the cbr
    instr_free(dr_context, d_insn);
  
    if (taken) {
      INFO("taken branch(evaluate_arm): %#lx -> %#lx", addr, target_addr);
    } else {
      // since not taken, target addr will be the next instruction
      target_addr = (uint64_t)addr + instr_length(dr_context, d_insn);
      INFO("continue from %#lx", target_addr);
    }
    return std::make_pair(target_addr, taken);
  #else
    return std::make_pair(UNKNOWN_ADDR, false);
  #endif
  }

void print_backtrace()
{
  return;
  unw_cursor_t cursor;
  unw_context_t context;

  unw_getcontext(&context);
  // unw_init_local(&cursor, &context);
  unw_init_local2(&cursor, &context, UNW_INIT_SIGNAL_FRAME);

  while (unw_step(&cursor) > 0)
  {
    unw_word_t offset, pc;
    char symbol[512];

    unw_get_reg(&cursor, UNW_REG_IP, &pc);

    if (unw_get_proc_name(&cursor, symbol, sizeof(symbol), &offset) == 0)
    {
      WARNING("[%lx] %s + 0x%lx\n", (unsigned long)pc, symbol, (unsigned long)offset);
    }
    else
    {
      WARNING("[%lx] <unknown>\n", (unsigned long)pc);
    }
  }
}

int tgkill(pid_t group_id, pid_t tid, int signo)
{
  return syscall(SYS_tgkill, group_id, tid, signo);
}

