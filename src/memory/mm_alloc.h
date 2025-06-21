/*
 * mm_alloc.h
 *
 * Exports a clone of the interface documented in "man 3 malloc".
 */

#pragma once

#ifndef _malloc_H_
#define _malloc_H_

#include <stdlib.h>
#include <stdbool.h>

typedef struct heap_block {
  struct heap_block* prev;
  struct heap_block* next;
  bool free;
  size_t size;
  void* memory;
} block_t;

void* mm_malloc(size_t size);
void* mm_realloc(void* ptr, size_t size);
void mm_free(void* ptr);

#endif