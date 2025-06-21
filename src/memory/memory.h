#pragma once

#include "threads/palloc.h"
#include "pagedir.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void* syscall_sbrk(intptr_t increment);