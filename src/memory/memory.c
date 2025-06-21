#include "memory.h"

static void* syscall_sbrk(intptr_t increment) {
  struct thread* t = thread_current();
  uint8_t* old_heap_break = t->heap_break;
  t->heap_break += increment;

  if (t->heap_break < t->heap_start) {
    t->heap_break = old_heap_break;
    return (void*)-1;
  }

  bool add = old_heap_break < t->heap_break;
  if (add) {
    uint8_t* counter = (uint8_t*)pg_round_up(old_heap_break);
    int num_pages_allocated = 0;
    while (counter < t->heap_break) {
      bool success = true;

      uint8_t* kpage = palloc_get_page(PAL_ZERO | PAL_USER);
      if (kpage != NULL) {
        success = pagedir_set_page(t->pagedir, counter, kpage, true);
        if (!success)
          palloc_free_page(kpage);
        else
          num_pages_allocated += 1;
      } else
        success = false;

      if (!success) {
        for (uint8_t* pb = counter - PGSIZE; pb >= old_heap_break; pb -= PGSIZE) {
          palloc_free_page(pagedir_get_page(t->pagedir, pb));
          pagedir_clear_page(t->pagedir, pb);
        }
        t->heap_break = old_heap_break;
        return (void*)-1;
      } else
        counter += PGSIZE;
    }
    //printf("%d pages allocated\n", num_pages_allocated);
  } else {
    uint8_t* counter = (uint8_t*)pg_round_down(old_heap_break);
    int num_pages_deallocated = 0;
    while (counter >= t->heap_break) {
      palloc_free_page(pagedir_get_page(t->pagedir, counter));
      pagedir_clear_page(t->pagedir, counter);
      counter -= PGSIZE;
      num_pages_deallocated += 1;
    }
    //printf("%d pages deallocated\n", num_pages_deallocated);
  }

  return old_heap_break;
}