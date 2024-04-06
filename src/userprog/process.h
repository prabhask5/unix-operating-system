#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127
#define MAX_ARGS 50

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* An open file. */
// NOTE: this was copied from file.c to be accessible in process.c
// I do not know why this was in file.c but this might break some abstraction barriers that we weren't supposed to break
struct file_descriptor_elem {
  char name[NAME_MAX];
  struct file* f;
  int id;
  struct list_elem elem;
};

/* Adds a new file description entry */
struct file_descriptor_elem* create_file_descriptor(const char* name, struct list* fdt);

//  Add shared data for traking process exit status for exec, wait, and exit
struct shared_data {
  struct semaphore semaphore;
  struct lock lock;
  int ref_cnt;
  int data;
  pid_t process_pid;
  struct list_elem elem;
};

// Add shared data for tracking process exit status for exec, wait, and exit
struct thread_list_elem {
  tid_t tid;
  struct shared_data* exit_status;
  struct list_elem elem;
};

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;     /* Page directory. */
  char process_name[16]; /* Name of the main thread */
  struct file* spawn_file;
  struct thread* main_thread; /* Pointer to main thread */
  struct list fdt;            /* List for the file descriptor table */
  struct shared_data*
      exit_code_data; /* Contains current processes exit information (shared with parent pcb in children_exit_code_data) */
  struct list children_exit_code_data; /* List of process_exit_code_t */
  struct list thread_list;             /* List of active threads in the process*/
  // gradescope said we needed this
  struct lock kernel_lock; /* Lock for the process */
  bool is_exiting;
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(int exit_code);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
