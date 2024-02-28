#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

// Global syscall lock
struct lock syscall_lock;

static void syscall_handler(struct intr_frame*);
static bool is_valid_addr(void* addr);
static bool syscall_validate_word(void* word);
static bool syscall_validate_ptr(void** ptr);
static bool syscall_validate_str(char* str);
static size_t syscall_validate_buffer(void* buffer, size_t size);

void syscall_init(void) {
  lock_init(&syscall_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*
  Validates the address for one byte of memory
*/
static bool is_valid_addr(void* addr) {
  return is_user_vaddr(addr) && pagedir_get_page(thread_current()->pcb->pagedir, addr) != NULL;
}

/*
 Must check for null pointers, invalid pointers (e.g. pointing to unmapped memory), 
 and illegal pointers (e.g. pointing to kernel memory). Beware: a 4-byte memory region 
 (e.g. a 32-bit integer) may consist of 2 bytes of valid memory and 2 bytes of invalid 
 memory, if the memory lies on a page boundary. You should handle these cases by 
 terminating the user process
*/
static bool syscall_validate_word(void* word) {
  // In general this validates 4 bytes of data (ptr, int, etc.)
  // Check first bytes of ptr and last bytes of ptr
  if (word == NULL || !is_valid_addr(word) || !is_valid_addr(word + sizeof(uint32_t) - 1)) {
    return false;
  }
  return true;
}

static bool syscall_validate_ptr(void** ptr) {
  // In general this validates 4 bytes of data (ptr, int, etc.)
  // Check first bytes of ptr and last bytes of ptr
  if (!syscall_validate_word(ptr))
    return false;
  if (!is_valid_addr(*ptr))
    return false;
  return true;
}

/* Takes in a char* and validates all memory from str[0] to the first null pointer */
static bool syscall_validate_str(char* str) {
  int i = 0;
  do {
    if (!is_valid_addr(str + i))
      return false;
    ++i;
  } while (str[i] != '\0');
  return true;
}

/* 
Validates all memory from start of buffer to the end of the buffer
(i.e. all memory between buffer[0] and buffer[size-1])
If the valid buffer size is less than the size_t then

TODO check to see if we can get away with only checking the first and last element
*/
static size_t syscall_validate_buffer(void* buffer, size_t size) {
  for (size_t i = 0; i < size; i++) {
    if (!is_valid_addr(buffer + i))
      return i;
  }
  return size;
}

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

  // Verify syscall id is located in valid user memory
  if (!syscall_validate_word(args)) {
    process_exit(-1);
    return;
  }

  if (args[0] == SYS_EXIT) {
    if (!syscall_validate_word(args + 4)) {
      process_exit(-1);
      return;
    }
    // TODO Update child process exit status
    f->eax = args[1];
    process_exit(args[1]);
  }

  else if (args[0] == SYS_PRACTICE) {
    if (!syscall_validate_word(args + 4)) {
      process_exit(-1);
      return;
    }
    f->eax = args[1] + 1;
  }

  else if (args[0] == SYS_WRITE) {

    // Verify buffer pointer and size are in valid user memory
    // fd, buffer, size
    if (!syscall_validate_word(args + 4) || !syscall_validate_ptr(args + 8) ||
        !syscall_validate_word(args + 12)) {
      process_exit(-1);
      return;
    }
    int size = syscall_validate_buffer(args[2], args[3]);

    lock_acquire(&syscall_lock);
    uint32_t bytes_written = 0;
    struct list* fdt = &thread_current()->pcb->fdt;
    // TODO validate args
    if (args[1] < list_size(fdt)) {
      // Get the entry and perform read / write
      int i = 0;
      struct file_descriptor_elem* fd;
      for (struct list_elem* e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
        if (i == args[1]) {
          fd = list_entry(e, struct file_descriptor_elem, elem);
          break;
        }
        ++i;
      }

      // TODO generalize this to more file descriptors
      if (strcmp(fd->name, "stdout") == 0 || strcmp(fd->name, "stderr") == 0) {
        // TODO breakup large buffers
        putbuf(args[2], size);
        bytes_written = size;
      }
    }
    // Return number of bytes written
    f->eax = bytes_written;
    lock_release(&syscall_lock);
  }
}