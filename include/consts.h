#ifndef CONSTS
#define CONSTS
#include <stdint.h>
#include <signal.h>
#include "buffer_manager.h"
const uint64_t UNKNOWN_ADDR = 0;
const uint64_t RINGBUFFER_SIZE = 16;
extern BufferManager* buffer_manager;
#endif