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
  struct file f;
  struct list_elem elem;
};

/* Adds a new file description entry */
struct file_descriptor_elem* create_file_descriptor(const char* name, struct list* fdt);

//  TODO Add shared data for traking process exit status for exec, wait, and exit

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  struct list fdt;            /* List for the file descriptor table */
  // TODO add shared data for tracking children exit status and parent wait calls
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
