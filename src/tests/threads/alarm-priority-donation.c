/* Checks that when the alarm clock wakes up threads, the
   higher-priority threads run first. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"

static thread_func sleeping_thread;
static thread_func prio_recipient_thread;
static thread_func prio_donor_thread;
static int64_t wake_time;
static struct semaphore wait_sema;

void test_alarm_priority_donation(void) {
  struct lock a;
  int i;

  /* This test is special among the alarm tests
     in that it requires the priority scheduler. */
  ASSERT(active_sched_policy == SCHED_PRIO);

  wake_time = timer_ticks() + 5 * TIMER_FREQ;
  sema_init(&wait_sema, 0);
  lock_init(&a);

  for (i = 0; i < 10; i++) {
    int priority = PRI_DEFAULT;
    char name[16];
    snprintf(name, sizeof name, "%d", i);
    thread_create(name, priority, sleeping_thread, NULL);
  }

  /* Create the thread that will get priority donation during sleep*/
  thread_create("priority recipient", PRI_MIN + 1, prio_recipient_thread, &a);

  /* Create the thread that will donate priority to the recipient thread, but allow
  recipient thread to acquire lock a first */
  thread_set_priority(PRI_MIN);
  thread_create("priority donor", PRI_MAX, prio_donor_thread, &a);

  for (i = 0; i < 12; i++)
    sema_down(&wait_sema);
}

static void sleeping_thread(void* aux UNUSED) {
  /* Busy-wait until the current time changes. */
  int64_t start_time = timer_ticks();
  while (timer_elapsed(start_time) == 0)
    continue;

  /* Now we know we're at the very beginning of a timer tick, so
     we can call timer_sleep() without worrying about races
     between checking the time and a timer interrupt. */
  timer_sleep(wake_time - timer_ticks());

  /* Print a message on wake-up. */
  msg("Sleeping thread %s woke up.", thread_name());

  sema_up(&wait_sema);
}

static void prio_recipient_thread(void* lock_) {
  /* Acquire lock a */
  struct lock* lock = lock_;
  lock_acquire(lock);
  msg("Recipient thread acquired lock a.");

  /* Busy-wait until the current time changes. */
  int64_t start_time = timer_ticks();
  while (timer_elapsed(start_time) == 0)
    continue;

  msg("Recipient thread sleeping.");

  /* Now we know we're at the very beginning of a timer tick, so
     we can call timer_sleep() without worrying about races
     between checking the time and a timer interrupt. */
  timer_sleep(wake_time - timer_ticks());

  /* Print a message on wake-up. */
  msg("Recipient thread woke up.");

  lock_release(lock);

  sema_up(&wait_sema);
}

static void prio_donor_thread(void* lock_) {
  /* Adjust timing so that donor thread will donate priority while recipient is sleeping */
  int64_t start_time = timer_ticks();
  while (timer_elapsed(start_time) == 0)
    continue;
  struct lock* lock = lock_;
  timer_sleep(wake_time - timer_ticks() - TIMER_FREQ);

  msg("Donor thread started.");
  lock_acquire(lock);
  msg("Donor thread acquired lock a.");
  lock_release(lock);
  msg("Donor thread finished.");
  sema_up(&wait_sema);
}
