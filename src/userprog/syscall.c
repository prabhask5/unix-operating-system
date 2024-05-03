#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <float.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "filesys/inode.h"
#include <string.h>
#include <stdlib.h>
// Global syscall lock
struct lock syscall_lock;

static void syscall_handler(struct intr_frame*);
static bool is_valid_addr(void* addr);
static bool syscall_validate_word(void* word);
static bool syscall_validate_ptr(void** ptr);
static bool syscall_validate_str(char* str_ptr);
static size_t syscall_validate_buffer(void* buffer, size_t size);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

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
static bool syscall_validate_str(char* str_ptr) {

  if (!is_valid_addr(str_ptr)) {
    return false;
  }

  int i = 0;
  while (is_valid_addr(str_ptr + i) && str_ptr[i] != '\0') {
    ++i;
  }
  return is_valid_addr(str_ptr + i);
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

int generate_fid() {
  static int cur_fid = 3;
  return ++cur_fid;
}

// static bool sys_mkdir(char *dir_path) {
//     char *path_copy;
//     struct dir *dir;
//     bool success = false;

//     path_copy = malloc(strlen(dir_path) + 1);
//     if (path_copy == NULL) return false;
//     strlcpy(path_copy, dir_path, strlen(dir_path)+1);

//     const char *next = path_copy;
//     char part[NAME_MAX + 1];
//     struct inode *inode = NULL;

//     dir = (path_copy[0] == '/') ? dir_open_root() : thread_current()->cwd;

//     while (get_next_part(part, &next) == 1) {
//         if (!dir_lookup(dir,part, &inode)) {
//             if (*next == '\0') { // This is the last part
//                 block_sector_t inode_sector = 0;
//                 if (free_map_allocate(1, &inode_sector)) {
//                     dir_create(inode_sector, 16);
//                     if (!dir_add(dir, part, inode_sector, true)) {
//                         free_map_release(inode_sector, 1);
//                         break;
//                     }
//                     success = true;
//                 }
//                 break;
//             } else {
//                 break; // Part of path does not exist and is not the last part
//             }
//         } else if (!inode_is_dir(inode)) {
//             inode_close(inode);
//             break; // Found a file where a directory was expected
//         } else { // Step into the next directory
//             struct dir *next_dir = dir_open(inode);
//             dir_close(dir);
//             dir = next_dir;
//         }

//     }

//     dir_close(dir);
//     free(path_copy);
//     return success;
// }

// static bool sys_mkdir(const char* dir_path) {
//   char* path_copy = malloc(strlen(dir_path) + 1);
//   if (path_copy == NULL)
//     return false;
//   strlcpy(path_copy, dir_path, strlen(dir_path) + 1);

//   char part[NAME_MAX + 1];
//   // struct dir* dir = (path_copy[0] == '/') ? dir_open_root() : dir_reopen(thread_current()->cwd);
//   struct dir* dir = dir_reopen(thread_current()->cwd);
//   ASSERT(inode_is_dir(dir->inode)== true);
//   if (dir == NULL) {
//     free(path_copy);
//     return false;
//   }

//   const char* next = path_copy;
//   struct inode* inode = NULL;
//   bool success = false;

//   while (get_next_part(part, &next) == 1) {
//     if (dir_lookup(dir, part, &inode)) {
//       if (*next == '\0' || !inode_is_dir(inode)) {
//         inode_close(inode);
//         break;
//       }
//       struct dir* next_dir = dir_open(inode);
//       inode_close(inode); // Close old inode after opening dir
//       dir_close(dir);     // Close current directory before moving to the next
//       dir = next_dir;
//     } else {
//       if (*next == '\0') { // This is the last part
//         block_sector_t inode_sector = 0;
//         if (free_map_allocate(1, &inode_sector) && dir_create(inode_sector, 16)) {
//           success = dir_add(dir, part, inode_sector, true);
//           if (!success) {
//             free_map_release(inode_sector, 1);
//           }
//         }
//         break;
//       } else {
//         break; // Part of path does not exist and is not the last part
//       }
//     }
//   }

//   dir_close(dir);
//   free(path_copy);
//   return success;
// }

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
    if (!syscall_validate_word(args + 1)) {
      process_exit(-1);
      return;
    }

    process_exit(args[1]);
    f->eax = args[1];
  }

  else if (args[0] == SYS_PRACTICE) {
    if (!syscall_validate_word(args + 1)) {
      process_exit(-1);
      return;
    }
    f->eax = args[1] + 1;
  }

  else if (args[0] == SYS_HALT) {
    shutdown_power_off();
    process_exit(0);
  }

  else if (args[0] == SYS_EXEC) {
    // if (!syscall_validate_word(args + 1) && !syscall_validate_str(*(args + 1))) {
    if (!syscall_validate_ptr(args + 1) || !syscall_validate_str(*(args + 1))) {
      process_exit(-1);
      return;
    }

    // process_execute will either return the child process id or -1 if the child process fails to load
    pid_t cpid = process_execute(args[1]);
    f->eax = cpid;
  }

  else if (args[0] == SYS_WAIT) {
    if (!syscall_validate_word(args + 1)) {
      process_exit(-1);
      return;
    }

    int wait_output = process_wait(args[1]);
    f->eax = wait_output;
  }

  else if (args[0] == SYS_WRITE) {

    // Verify buffer pointer and size are in valid user memory
    // fd, buffer, size
    if (!syscall_validate_word(args + 1) || !syscall_validate_ptr(args + 2) ||
        !syscall_validate_word(args + 3)) {
      process_exit(-1);
      return;
    }

    int size = syscall_validate_buffer(args[2], args[3]);

    uint32_t bytes_written = 0;

    if (args[1] == STDIN_FILENO) {
      // TODO breakup large buffers

      f->eax = -1;
      return;

    } else if (args[1] == STDOUT_FILENO) {
      // TODO breakup large buffers
      putbuf(args[2], size);
      bytes_written = size;

    } else {

      struct list* fdt = &thread_current()->pcb->fdt;

      // Get the entry and perform read / write

      struct file_descriptor_elem* fd = NULL;
      for (struct list_elem* e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
        struct file_descriptor_elem* temp_fd = list_entry(e, struct file_descriptor_elem, elem);
        if (temp_fd->id == args[1])
          fd = temp_fd;
      }

      if (fd == NULL || inode_is_dir(file_get_inode(fd->f))) {
        f->eax = -1;
        return;
      }

      bytes_written = file_write(fd->f, args[2], size);
    }

    if (bytes_written == -1) {
      f->eax = -1;
      return;
    }

    // Return number of bytes written
    f->eax = bytes_written;
    return;

  }

  else if (args[0] == SYS_CREATE) {

    // we want args[1] and args[2]
    if (!syscall_validate_ptr(args + 1) || !syscall_validate_str(args + 1) ||
        !syscall_validate_word(args + 2)) {
      process_exit(-1);
      return;
    }

    bool retval = filesys_create(args[1], args[2]);

    f->eax = retval;
    return;

  } else if (args[0] == SYS_REMOVE) {
    // we want args[1]
    if (!syscall_validate_word(args + 1)) {
      process_exit(-1);
      return;
    }

    int retval = filesys_remove(args[1]);
    f->eax = retval;
    return;
  } else if (args[0] == SYS_OPEN) {

    if (!syscall_validate_ptr(args + 1)) {

      process_exit(-1);
      return;
    }
    struct file* file = filesys_open((char*)args[1]);

    if (file == NULL) {

      f->eax = -1;
      return;
    }

    struct file_descriptor_elem* fd = malloc(sizeof(struct file_descriptor_elem));

    fd->f = file;
    fd->id = generate_fid();

    list_push_back(&thread_current()->pcb->fdt, &fd->elem);

    f->eax = fd->id;
    return;

  } else if (args[0] == SYS_FILESIZE) {

    if (!syscall_validate_word(args + 1)) {
      process_exit(-1);
      return;
    }

    int32_t len;

    struct list* fdt = &thread_current()->pcb->fdt;
    struct file_descriptor_elem* fd;

    for (struct list_elem* e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {

      fd = list_entry(e, struct file_descriptor_elem, elem);
      if (args[1] == fd->id) {
        len = file_length(fd->f);
      }
    }

    f->eax = len;
    return;
  } else if (args[0] == SYS_READ) {

    // Verify buffer pointer and size are in valid user memory
    // fd, buffer, size
    if (!syscall_validate_word(args + 1) || !syscall_validate_ptr(args + 2) ||
        !syscall_validate_word(args + 3)) {
      process_exit(-1);
      return;
    }

    int size = syscall_validate_buffer(args[2], args[3]);

    uint32_t bytes_read = 0;
    struct list* fdt = &thread_current()->pcb->fdt;

    // Get the entry and perform read / write

    struct file_descriptor_elem* fd = NULL;
    for (struct list_elem* e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
      struct file_descriptor_elem* temp_fd = list_entry(e, struct file_descriptor_elem, elem);
      if (temp_fd->id == args[1])
        fd = temp_fd;
    }

    if (fd == NULL) {
      f->eax = -1;
      return;
    }

    if (args[1] == STDIN_FILENO) {
      // TODO breakup large buffers
      uint8_t key = input_getc();
      bytes_read = 1;
    } else {
      bytes_read = file_read(fd->f, args[2], size);
    }

    if (bytes_read == -1) {
      f->eax = -1;
      return;
    }

    // Return number of bytes written
    f->eax = bytes_read;
    return;

  } else if (args[0] == SYS_SEEK) {
    if (!syscall_validate_word(args + 1) || !syscall_validate_word(args + 2)) {
      process_exit(-1);
      return;
    }

    struct list* fdt = &thread_current()->pcb->fdt;

    struct file_descriptor_elem* fd = NULL;
    for (struct list_elem* e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
      struct file_descriptor_elem* temp_fd = list_entry(e, struct file_descriptor_elem, elem);
      if (temp_fd->id == args[1])
        fd = temp_fd;
    }

    if (fd == NULL) {
      f->eax = -1;
      return;
    }

    file_seek(fd->f, args[2]);

    return;
  } else if (args[0] == SYS_TELL) {
    if (!syscall_validate_word(args + 1)) {
      process_exit(-1);
      return;
    }

    struct list* fdt = &thread_current()->pcb->fdt;
    struct file_descriptor_elem* fd = NULL;
    for (struct list_elem* e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
      struct file_descriptor_elem* temp_fd = list_entry(e, struct file_descriptor_elem, elem);
      if (temp_fd->id == args[1])
        fd = temp_fd;
    }

    if (fd == NULL) {
      f->eax = -1;
      return;
    }

    int offset = file_tell(fd->f);

    f->eax = offset;
    return;

  } else if (args[0] == SYS_CLOSE) {
    if (!syscall_validate_word(args + 1)) {
      process_exit(-1);
      return;
    }

    struct list* fdt = &thread_current()->pcb->fdt;
    struct file_descriptor_elem* fd = NULL;

    struct list_elem* e = NULL;
    for (e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {

      struct file_descriptor_elem* temp_fd = list_entry(e, struct file_descriptor_elem, elem);
      if (temp_fd->id == args[1]) {
        fd = temp_fd;
        break;
      }
    }

    if (fd == NULL) {
      f->eax = -1;
      return;
    }

    list_remove(e);
    file_close(fd->f);
    free(fd);

    return;
  }

  else if (args[0] == SYS_COMPUTE_E) {
    if (args[1] < 0) {
      process_exit(-1);
      return;
    }
    f->eax = sys_sum_to_e(args[1]);
  }

  else if (args[0] == SYS_CHDIR) {
    if (!syscall_validate_str(args + 1)) {
      f->eax = false;
      return;
    }

    if (!filesys_chdir(args[1])) {
      f->eax = false;
      return;
    }

    f->eax = true;
    return;
  }

  else if (args[0] == SYS_MKDIR) {

    if (!syscall_validate_str(args + 1)) {
      f->eax = false;
      return;
    }

    f->eax = filesys_mkdir(args[1]);
    return;
  }

  else if (args[0] == SYS_ISDIR) {
    // !!!!UNTESTED
    if (!syscall_validate_word(args + 1)) {
      f->eax = false;
      return;
    }

    struct list* fdt = &thread_current()->pcb->fdt;

    struct file_descriptor_elem* fd = NULL;
    for (struct list_elem* e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
      struct file_descriptor_elem* temp_fd = list_entry(e, struct file_descriptor_elem, elem);
      if (temp_fd->id == args[1])
        fd = temp_fd;
    }

    struct inode* inode = file_get_inode(fd->f);
    if (!inode) {
      f->eax = false;
      return;
    }

    f->eax = inode_is_dir(inode);
    return;
  } else if (args[0] == SYS_INUMBER) {

    if (!syscall_validate_word(args + 1)) {
      f->eax = -1;
      return;
    }

    struct list* fdt = &thread_current()->pcb->fdt;

    struct file_descriptor_elem* fd = NULL;
    for (struct list_elem* e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
      struct file_descriptor_elem* temp_fd = list_entry(e, struct file_descriptor_elem, elem);
      if (temp_fd->id == args[1])
        fd = temp_fd;
    }

    struct inode* inode = file_get_inode(fd->f);
    if (!inode) {
      f->eax = -1;
      return;
    }

    f->eax = inode_get_inumber(inode);
    return;

  }

  else if (args[0] == SYS_READDIR) {

    if (!syscall_validate_word(args + 1) || !syscall_validate_str(args + 2)) {
      f->eax = false;
      return;
    }

    struct list* fdt = &thread_current()->pcb->fdt;

    struct file_descriptor_elem* fd = NULL;
    for (struct list_elem* e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
      struct file_descriptor_elem* temp_fd = list_entry(e, struct file_descriptor_elem, elem);
      if (temp_fd->id == args[1])
        fd = temp_fd;
    }

    struct inode* inode = file_get_inode(fd->f);
    if (!inode) {
      f->eax = false;
      return;
    }

    if (!inode_is_dir(inode)) {
      f->eax = false;
      return;
    }

    f->eax = dir_readdir(fd->f, args[2]);

    return;
  }
}
