#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  // TODO parse and validate syscall args, call syscalls
  // https://cs162.org/static/proj/proj-userprog/docs/tasks/process-control-syscalls/
  // https://cs162.org/static/proj/proj-userprog/docs/tasks/file-operation-syscalls/

  // int practice (int i)
  // void halt (void)
  // void exit (int status)
  // pid_t exec (const char *cmd_line)
  //    See pid_t process_execute(const char* file_name)
  // int wait (pid_t pid)
  //    See int process_wait(pid_t child_pid UNUSED)

  // File syscalls (Wrap in global lock for project 1)
  // bool create (const char *file, unsigned initial_size)
  // bool remove (const char *file)
  // int open (const char *file)
  // int filesize (int fd)
  // int read (int fd, void *buffer, unsigned size)
  // int write (int fd, const void *buffer, unsigned size)
  // void seek (int fd, unsigned position)
  // int tell(int fd)
  // void close (int fd)

  // Floating Point
  // double compute_e (int n)

  /* printf("System call number: %d\n", args[0]); */

  if (args[0] == SYS_EXIT) {
    // TODO Update child process exit status
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  }
}
