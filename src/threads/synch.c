/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

void rehash_waiter(struct thread*);
bool priority_less_sema(struct list_elem*, struct list_elem*, void* aux UNUSED);
bool priority_less_cond(struct list_elem*, struct list_elem*, void* aux UNUSED);

bool priority_less_sema(struct list_elem* a, struct list_elem* b, void* aux UNUSED) {
  const struct thread* thread_a = list_entry(a, struct thread, elem);
  const struct thread* thread_b = list_entry(b, struct thread, elem);
  return thread_get_other_priority(thread_a) <= thread_get_other_priority(thread_b);
}

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void sema_init(struct semaphore* sema, unsigned value) {
  ASSERT(sema != NULL);

  sema->value = value;
  list_init(&sema->waiters_priority_array);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void sema_down(struct semaphore* sema) {
  enum intr_level old_level;

  ASSERT(sema != NULL);
  ASSERT(!intr_context());

  old_level = intr_disable();
  struct thread* t = thread_current();

  while (sema->value == 0) {
    list_insert_ordered(&sema->waiters_priority_array, &t->elem, priority_less_sema, NULL);
    t->waiting_for_sema = sema;
    thread_block();
    t->waiting_for_sema = NULL;
  }
  sema->value--;
  intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore* sema) {
  enum intr_level old_level;
  bool success;

  ASSERT(sema != NULL);

  old_level = intr_disable();
  if (sema->value > 0) {
    sema->value--;
    success = true;
  } else
    success = false;
  intr_set_level(old_level);

  return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void sema_up(struct semaphore* sema) {
  enum intr_level old_level;

  ASSERT(sema != NULL);

  old_level = intr_disable();

  sema->value++;
  if (!list_empty(&sema->waiters_priority_array)) {
    struct thread* awoken_thread =
        list_entry(list_pop_back(&sema->waiters_priority_array), struct thread, elem);
    thread_unblock(awoken_thread);
    if (thread_get_other_priority(awoken_thread) > thread_get_priority()) {
      if (!intr_context()) {
        thread_yield();
      } else {
        intr_yield_on_return();
      }
    }
  }

  intr_set_level(old_level);
}

static void sema_test_helper(void* sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void) {
  struct semaphore sema[2];
  int i;

  printf("Testing semaphores...");
  sema_init(&sema[0], 0);
  sema_init(&sema[1], 0);
  thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++) {
    sema_up(&sema[0]);
    sema_down(&sema[1]);
  }
  printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void sema_test_helper(void* sema_) {
  struct semaphore* sema = sema_;
  int i;

  for (i = 0; i < 10; i++) {
    sema_down(&sema[0]);
    sema_up(&sema[1]);
  }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init(struct lock* lock) {
  ASSERT(lock != NULL);

  lock->holder = NULL;
  sema_init(&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void lock_acquire(struct lock* lock) {
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(!lock_held_by_current_thread(lock));

  enum intr_level old_level;

  old_level = intr_disable();
  struct thread* curr = thread_current();

  if (!lock_try_acquire(lock)) {
    struct thread* g_thread = curr;
    struct thread* r_thread = lock->holder;

    while (r_thread != NULL &&
           thread_get_other_priority(g_thread) > thread_get_other_priority(r_thread)) {
      int donation = thread_get_other_priority(g_thread) - r_thread->priority;
      set_priority_donation(r_thread, donation);
      g_thread = r_thread;
      if (r_thread->waiting_for_lock != NULL)
        r_thread = r_thread->waiting_for_lock->holder;
      else
        r_thread = NULL;
    }

    curr->waiting_for_lock = lock;
    sema_down(&lock->semaphore);
    curr->waiting_for_lock = NULL;

    lock->holder = curr;
    list_push_back(&curr->held_locks, &lock->elem);
  }

  intr_set_level(old_level);
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock* lock) {
  bool success;

  ASSERT(lock != NULL);
  ASSERT(!lock_held_by_current_thread(lock));

  success = sema_try_down(&lock->semaphore);
  if (success) {
    lock->holder = thread_current();
    list_push_back(&thread_current()->held_locks, &lock->elem);
  }
  return success;
}

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void lock_release(struct lock* lock) {
  ASSERT(lock != NULL);
  ASSERT(lock_held_by_current_thread(lock));

  enum intr_level old_level;

  old_level = intr_disable();

  list_remove(&lock->elem);
  int new_highest_waiting_priority = 0;
  for (struct list_elem* e = list_begin(&thread_current()->held_locks);
       e != list_end(&thread_current()->held_locks); e = list_next(e)) {
    struct lock* held_lock = list_entry(e, struct lock, elem);
    if (!list_empty(&held_lock->semaphore.waiters_priority_array)) {
      int p = thread_get_other_priority(
          list_entry(list_back(&held_lock->semaphore.waiters_priority_array), struct thread, elem));
      if (p > new_highest_waiting_priority)
        new_highest_waiting_priority = p;
    }
  }

  if (new_highest_waiting_priority > thread_current()->priority) {
    set_priority_donation(thread_current(),
                          new_highest_waiting_priority - thread_current()->priority);
  } else if (thread_current()->priority_donation > 0) {
    set_priority_donation(thread_current(), 0);
  }

  lock->holder = NULL;
  sema_up(&lock->semaphore);

  intr_set_level(old_level);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock* lock) {
  ASSERT(lock != NULL);

  return lock->holder == thread_current();
}

/* Initializes a readers-writers lock */
void rw_lock_init(struct rw_lock* rw_lock) {
  lock_init(&rw_lock->lock);
  cond_init(&rw_lock->read);
  cond_init(&rw_lock->write);
  rw_lock->AR = rw_lock->WR = rw_lock->AW = rw_lock->WW = 0;
}

/* Acquire a writer-centric readers-writers lock */
void rw_lock_acquire(struct rw_lock* rw_lock, bool reader) {
  // Must hold the guard lock the entire time
  lock_acquire(&rw_lock->lock);

  if (reader) {
    // Reader code: Block while there are waiting or active writers
    while ((rw_lock->AW + rw_lock->WW) > 0) {
      rw_lock->WR++;
      cond_wait(&rw_lock->read, &rw_lock->lock);
      rw_lock->WR--;
    }
    rw_lock->AR++;
  } else {
    // Writer code: Block while there are any active readers/writers in the system
    while ((rw_lock->AR + rw_lock->AW) > 0) {
      rw_lock->WW++;
      cond_wait(&rw_lock->write, &rw_lock->lock);
      rw_lock->WW--;
    }
    rw_lock->AW++;
  }

  // Release guard lock
  lock_release(&rw_lock->lock);
}

/* Release a writer-centric readers-writers lock */
void rw_lock_release(struct rw_lock* rw_lock, bool reader) {
  // Must hold the guard lock the entire time
  lock_acquire(&rw_lock->lock);

  if (reader) {
    // Reader code: Wake any waiting writers if we are the last reader
    rw_lock->AR--;
    if (rw_lock->AR == 0 && rw_lock->WW > 0)
      cond_signal(&rw_lock->write, &rw_lock->lock);
  } else {
    // Writer code: First try to wake a waiting writer, otherwise all waiting readers
    rw_lock->AW--;
    if (rw_lock->WW > 0)
      cond_signal(&rw_lock->write, &rw_lock->lock);
    else if (rw_lock->WR > 0)
      cond_broadcast(&rw_lock->read, &rw_lock->lock);
  }

  // Release guard lock
  lock_release(&rw_lock->lock);
}

bool priority_less_cond(struct list_elem* a, struct list_elem* b, void* aux UNUSED) {
  const struct semaphore_elem* selem_a = list_entry(a, struct semaphore_elem, elem);
  const struct semaphore_elem* selem_b = list_entry(b, struct semaphore_elem, elem);
  return thread_get_other_priority(selem_a->waiting_thread) <=
         thread_get_other_priority(selem_b->waiting_thread);
}

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition* cond) {
  ASSERT(cond != NULL);

  list_init(&cond->waiters_priority_array);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait(struct condition* cond, struct lock* lock) {
  struct semaphore_elem waiter;

  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  waiter.waiting_thread = thread_current();
  sema_init(&waiter.semaphore, 0);
  list_insert_ordered(&cond->waiters_priority_array, &waiter.elem, priority_less_cond, NULL);
  lock_release(lock);
  thread_current()->waiting_for_cond = cond;
  sema_down(&waiter.semaphore);
  lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal(struct condition* cond, struct lock* lock UNUSED) {
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);
  ASSERT(!intr_context());
  ASSERT(lock_held_by_current_thread(lock));

  if (!list_empty(&cond->waiters_priority_array)) {
    thread_current()->waiting_for_cond = NULL;
    sema_up(&list_entry(list_pop_back(&cond->waiters_priority_array), struct semaphore_elem, elem)
                 ->semaphore);
  }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition* cond, struct lock* lock) {
  ASSERT(cond != NULL);
  ASSERT(lock != NULL);

  while (!list_empty(&cond->waiters_priority_array))
    cond_signal(cond, lock);
}

/* Put thread on the semaphore wait queue for the correct effective priority of thread. This function must be called with interrupts off. */
void rehash_waiter(struct thread* t) {
  if (t->waiting_for_sema) {
    list_insert_ordered(&t->waiting_for_sema->waiters_priority_array, &t->elem, priority_less_sema,
                        NULL);
  }

  if (t->waiting_for_cond) {
    struct semaphore_elem* waiter;

    for (struct list_elem* e = list_begin(&t->waiting_for_cond->waiters_priority_array);
         e = list_end(&t->waiting_for_cond->waiters_priority_array);) {
      struct semaphore_elem* curr = list_entry(e, struct semaphore_elem, elem);
      e = list_next(e);

      if (curr->waiting_thread == t) {
        list_remove(&curr->elem);
        waiter = curr;
        break;
      }
    }
    list_insert_ordered(&t->waiting_for_cond->waiters_priority_array, &waiter->elem,
                        priority_less_cond, NULL);
  }
}

bool user_lock_init(char* lock) {
  lock_acquire(&thread_current()->pcb->kernel_lock);
  struct process* curr_pcb = thread_current()->pcb;
  if (lock == NULL || curr_pcb->next_lock > 255) {
    lock_release(&thread_current()->pcb->kernel_lock);
    return false;
  }

  struct lock* curr_lock = malloc(sizeof(struct lock));
  if (curr_lock == NULL) {
    lock_release(&thread_current()->pcb->kernel_lock);
    return false;
  }

  lock_init(curr_lock);
  curr_pcb->user_locks[curr_pcb->next_lock] = curr_lock;
  *lock = curr_pcb->next_lock;
  curr_pcb->next_lock++;

  lock_release(&thread_current()->pcb->kernel_lock);
  return true;
}

bool user_lock_acquire(char* lock) {
  lock_acquire(&thread_current()->pcb->kernel_lock);
  struct process* curr_pcb = thread_current()->pcb;
  if (lock == NULL || 0 > *lock || *lock >= curr_pcb->next_lock) {
    lock_release(&thread_current()->pcb->kernel_lock);
    return false;
  }

  struct lock* mapped_lock = curr_pcb->user_locks[*lock];
  if (lock_held_by_current_thread(mapped_lock)) {
    lock_release(&thread_current()->pcb->kernel_lock);
    return false;
  }

  lock_release(&thread_current()->pcb->kernel_lock);
  lock_acquire(mapped_lock);
  return true;
}

bool user_lock_release(char* lock) {
  lock_acquire(&thread_current()->pcb->kernel_lock);
  struct process* curr_pcb = thread_current()->pcb;
  if (lock == NULL || 0 > *lock || *lock >= curr_pcb->next_lock) {
    lock_release(&thread_current()->pcb->kernel_lock);
    return false;
  }

  struct lock* mapped_lock = curr_pcb->user_locks[*lock];
  if (!lock_held_by_current_thread(mapped_lock)) {
    lock_release(&thread_current()->pcb->kernel_lock);
    return false;
  }

  lock_release(&thread_current()->pcb->kernel_lock);
  lock_release(mapped_lock);
  return true;
}

bool user_sema_init(char* sema, int val) {
  lock_acquire(&thread_current()->pcb->kernel_lock);
  struct process* curr_pcb = thread_current()->pcb;
  if (sema == NULL || curr_pcb->next_semaphore > 255 || val < 0) {
    lock_release(&thread_current()->pcb->kernel_lock);
    return false;
  }

  struct semaphore* curr_sema = malloc(sizeof(struct semaphore));
  if (curr_sema == NULL) {
    lock_release(&thread_current()->pcb->kernel_lock);
    return false;
  }

  sema_init(curr_sema, val);
  curr_pcb->user_semaphores[curr_pcb->next_semaphore] = curr_sema;
  *sema = curr_pcb->next_semaphore;
  curr_pcb->next_semaphore++;

  lock_release(&thread_current()->pcb->kernel_lock);
  return true;
}

bool user_sema_down(char* sema) {
  lock_acquire(&thread_current()->pcb->kernel_lock);
  struct process* curr_pcb = thread_current()->pcb;
  if (sema == NULL || 0 > *sema || *sema >= curr_pcb->next_semaphore) {
    lock_release(&thread_current()->pcb->kernel_lock);
    return false;
  }

  lock_release(&thread_current()->pcb->kernel_lock);
  sema_down(curr_pcb->user_semaphores[*sema]);
  return true;
}

bool user_sema_up(char* sema) {
  lock_acquire(&thread_current()->pcb->kernel_lock);
  struct process* curr_pcb = thread_current()->pcb;
  if (sema == NULL || 0 > *sema || *sema >= curr_pcb->next_semaphore) {
    lock_release(&thread_current()->pcb->kernel_lock);
    return false;
  }

  lock_release(&thread_current()->pcb->kernel_lock);
  sema_up(curr_pcb->user_semaphores[*sema]);
  return true;
}