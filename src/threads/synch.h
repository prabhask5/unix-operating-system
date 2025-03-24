#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore {
  unsigned value;                     /* Current value. */
  struct list waiters_priority_array; /* List of waiting threads. */
};

void sema_init(struct semaphore*, unsigned value);
void sema_down(struct semaphore*);
bool sema_try_down(struct semaphore*);
void sema_up(struct semaphore*);
void sema_self_test(void);

/* Lock. */
struct lock {
  struct thread* holder;      /* Thread holding lock (for debugging). */
  struct semaphore semaphore; /* Binary semaphore controlling access. */
  struct list_elem elem;
};

void lock_init(struct lock*);
void lock_acquire(struct lock*);
bool lock_try_acquire(struct lock*);
void lock_release(struct lock*);
bool lock_held_by_current_thread(const struct lock*);

/* One semaphore in a list. */
struct semaphore_elem {
  struct list_elem elem;         /* List element. */
  struct semaphore semaphore;    /* This semaphore. */
  struct thread* waiting_thread; /* The only thread that is waiting for this semaphore */
};

/* Condition variable. */
struct condition {
  struct list waiters_priority_array; /* List of waiting threads. */
};

void cond_init(struct condition*);
void cond_wait(struct condition*, struct lock*);
void cond_signal(struct condition*, struct lock* UNUSED);
void cond_broadcast(struct condition*, struct lock*);

/* Readers-writers lock. */
#define RW_READER 1
#define RW_WRITER 0

struct rw_lock {
  struct lock lock;
  struct condition read, write;
  int AR, WR, AW, WW;
};

void rw_lock_init(struct rw_lock*);
void rw_lock_acquire(struct rw_lock*, bool reader);
void rw_lock_release(struct rw_lock*, bool reader);

bool user_lock_init(char*);
bool user_lock_acquire(char*);
bool user_lock_release(char*);

bool user_sema_init(char*, int);
bool user_sema_down(char*);
bool user_sema_up(char*);

/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile("" : : : "memory")

#endif /* threads/synch.h */
