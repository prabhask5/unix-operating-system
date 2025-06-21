/*
 * mm_alloc.c
 */

#include "mm_alloc.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

block_t dummy = {NULL, NULL, 0, 0, NULL};

void print_ll() {
  for (block_t* curr = dummy.next; curr != NULL; curr = curr->next) {
    printf("%p %p %p %s %d %p\n", curr, curr->prev, curr->next, curr->free ? "free" : "not free",
           (int)curr->size, curr->memory);
  }
  printf("end of ll\n");
}

void* mm_malloc(size_t size) {
  if (size == 0)
    return NULL;

  block_t* prev = &dummy;
  for (block_t* curr = dummy.next; curr != NULL; curr = curr->next) {
    if (curr->free && curr->size >= size) {
      if (curr->size - size > sizeof(block_t)) {
        block_t* new_node = (block_t*)(curr->memory + size);
        new_node->prev = curr;
        new_node->next = curr->next;
        new_node->free = true;
        new_node->size = curr->size - (size + sizeof(block_t));
        new_node->memory = curr->memory + size + sizeof(block_t);

        curr->next = new_node;
        curr->size = size;
      }

      curr->free = false;
      memset(curr->memory, 0, curr->size);

      return curr->memory;
    }
    prev = curr;
  }

  void* res = sbrk(sizeof(block_t) + size);
  if (res == (void*)-1)
    return NULL;

  block_t* new_node = (block_t*)res;
  new_node->size = size;
  new_node->free = false;
  new_node->prev = prev;
  new_node->memory = (void*)new_node + sizeof(block_t);

  prev->next = new_node;

  memset(new_node->memory, 0, new_node->size);

  return new_node->memory;
}

void* mm_realloc(void* ptr, size_t size) {
  void* new_block = mm_malloc(size);
  bool malloc_failed = new_block == NULL;

  if (!malloc_failed && ptr != NULL) {
    size_t old_size = ((block_t*)(ptr - sizeof(block_t)))->size;
    size_t move_size;
    if (old_size > size)
      move_size = size;
    else
      move_size = old_size;

    memcpy(new_block, ptr, move_size);
  }

  if (!malloc_failed || size == 0)
    mm_free(ptr);
  return new_block;
}

void mm_free(void* ptr) {
  if (ptr == NULL)
    return;

  block_t* curr = (block_t*)(ptr - sizeof(block_t));
  curr->free = true;

  block_t* prev = curr->prev;
  block_t* next = curr->next;

  if (prev->free) {
    prev->next = next;
    if (next)
      next->prev = prev;
    curr->prev = curr->next = NULL;
    prev->size += sizeof(block_t) + curr->size;

    curr = prev;
  }

  if (next != NULL && next->free) {
    block_t* next_next = next->next;

    curr->next = next_next;
    if (next_next)
      next_next->prev = curr;
    next->prev = next->next = NULL;

    curr->size += sizeof(block_t) + next->size;
  }

  memset(curr->memory, 0, curr->size);
}
