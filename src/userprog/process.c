#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void start_process(void** args);
static void start_pthread(void** args);
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp);
void fdt_destroy(struct list* fdt);

struct shared_data* initialize_shared_data(pid_t pid);
int wait_for_data(struct shared_data* shared_data);
void save_data(struct shared_data* shared_data, int data);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;
  // printf("userprog init");

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;
  t->pcb->main_thread = t;

  list_init(&(t->pcb->children_exit_code_data));
  struct shared_data* exit_code_data = initialize_shared_data(t->tid);
  struct shared_data* child_pid_data = initialize_shared_data(t->tid);

  success = success && exit_code_data != NULL;
  success = success && child_pid_data != NULL;

  if (exit_code_data != NULL)
    t->pcb->exit_code_data = exit_code_data;
  if (child_pid_data != NULL)
    t->pcb->child_pid_data = child_pid_data;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
}

struct shared_data* initialize_shared_data(pid_t pid) {
  struct shared_data* shared_data = (struct shared_data*)malloc(sizeof(struct shared_data));
  if (shared_data == NULL)
    return shared_data;

  sema_init(&shared_data->semaphore, 0);
  lock_init(&shared_data->lock);
  shared_data->ref_cnt = 2;
  shared_data->data = -1;
  shared_data->process_pid = pid;

  return shared_data;
}

int wait_for_data(struct shared_data* shared_data) {
  sema_down(&shared_data->semaphore);
  int data = shared_data->data;
  lock_acquire(&shared_data->lock);
  int ref_cnt = --shared_data->ref_cnt;
  lock_release(&shared_data->lock);
  if (ref_cnt == 0)
    free(shared_data);
  return data;
}

void save_data(struct shared_data* shared_data, int data) {
  shared_data->data = data;
  sema_up(&shared_data->semaphore);
  lock_acquire(&shared_data->lock);
  int ref_cnt = --shared_data->ref_cnt;
  lock_release(&shared_data->lock);
  if (ref_cnt == 0)
    free(shared_data);
}

/* Adds a new file description entry */
struct file_descriptor_elem* create_file_descriptor(const char* name, struct list* fdt) {
  struct file_descriptor_elem* fd = malloc(sizeof(struct file_descriptor_elem));
  if (fd != NULL) {
    strlcpy(fd->name, name, strlen(name) + 1);
    memset(&fd->f, 0, sizeof(fd->f));
    list_push_back(fdt, &fd->elem);
  }
  return fd;
}

void fdt_destroy(struct list* fdt) {
  struct file_descriptor_elem* fd;
  struct list_elem* elem_to_remove;
  for (struct list_elem* e = list_begin(fdt); e != list_end(fdt);) {
    fd = list_entry(e, struct file_descriptor_elem, elem);
    elem_to_remove = e;
    e = list_next(e);
    list_remove(elem_to_remove);
    file_close(fd->f);
    free(fd);
  }
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  struct shared_data* child_pid_data = initialize_shared_data(thread_current()->tid);

  void* start_process_args[3];
  start_process_args[0] = fn_copy;
  start_process_args[1] = thread_current()->pcb;
  start_process_args[2] = child_pid_data;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, start_process_args);
  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);

  // Intialize shared datastructure for monitoring process return status
  // process_wait should be able to wait on this datastructure
  // shared data should automatically deallocate once ref_cnt == 0

  // for the initial process made in userprog_init, all the shared data is not initialized
  return wait_for_data(child_pid_data);
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void** args) {
  char* file_name = (char*)args[0];

  struct process* parent_pcb = (struct process*)args[1];
  struct shared_data* child_pid_data = (struct shared_data*)args[2];

  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  struct thread_list_elem* tle = malloc(sizeof(struct thread_list_elem));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);

    // Init the file descriptor table
    // 0 - stdin, 1 - stdout, 2 - stderr
    list_init(&(t->pcb->fdt));
    success = success && create_file_descriptor("stdin", &(t->pcb->fdt)) != NULL;
    success = success && create_file_descriptor("stdout", &(t->pcb->fdt)) != NULL;
    success = success && create_file_descriptor("stderr", &(t->pcb->fdt)) != NULL;

    list_init(&(t->pcb->children_exit_code_data));
    list_init(&(t->pcb->thread_list));

    // Init the lock
    lock_init(&(t->pcb->kernel_lock));

    // Push the current thread on to the pcb
    tle->tid = t->tid;
    // tle->exit_status = child_pid_data;
    tle->exit_status = initialize_shared_data(thread_current()->tid);
    list_push_back(&(t->pcb->thread_list), &(tle->elem));

    struct shared_data* exit_code_data = initialize_shared_data(t->tid);
    struct shared_data* child_pid_data = initialize_shared_data(t->tid);

    success = success && exit_code_data != NULL;
    success = success && child_pid_data != NULL;

    if (exit_code_data != NULL)
      t->pcb->exit_code_data = exit_code_data;
    if (child_pid_data != NULL)
      t->pcb->child_pid_data = child_pid_data;
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    success = load(file_name, &if_.eip, &if_.esp);

    uint8_t curr_fpu_state[108];
    asm volatile("fsave (%0)" ::"g"(curr_fpu_state) : "memory");
    asm volatile("finit");
    asm volatile("fsave (%0)" ::"g"(&if_.fpu) : "memory");
    asm volatile("frstor (%0)" ::"g"(curr_fpu_state) : "memory");
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    fdt_destroy(&(pcb_to_free->fdt));
    if (pcb_to_free->exit_code_data != NULL)
      free(pcb_to_free->exit_code_data);
    if (pcb_to_free->child_pid_data != NULL)
      free(pcb_to_free->child_pid_data);
    free(pcb_to_free);
    free(tle);
  }

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  if (!success) {
    save_data(child_pid_data, -1);
    thread_exit();
  } else {

    struct file* file = filesys_open(t->pcb->process_name);
    t->pcb->spawn_file = file;

    if (file != NULL) {
      file_deny_write(file);
    }

    list_push_back(&(parent_pcb->children_exit_code_data), &(t->pcb->exit_code_data->elem));
    save_data(child_pid_data, t->tid);
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  // waits for shared data to become available
  // Use PCB of the child process
  // Retreive data from child PCB and modify so wait can only be called once

  for (struct list_elem* e = list_begin(&thread_current()->pcb->children_exit_code_data);
       e != list_end(&thread_current()->pcb->children_exit_code_data); e = list_next(e)) {
    struct shared_data* item = list_entry(e, struct shared_data, elem);
    if (item->process_pid == child_pid) {
      list_remove(e);
      int exit_code = wait_for_data(item);
      return exit_code;
    }
  }
  return -1;
}

/* Free the current process's resources. */
void process_exit(int exit_code) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, exit_code);
  save_data(cur->pcb->exit_code_data, exit_code);

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  if (cur->pcb->spawn_file != NULL) {
    file_allow_write(cur->pcb->spawn_file);
    file_close(cur->pcb->spawn_file);
    cur->pcb->spawn_file = NULL; // Prevent dangling pointer
  }

  /* Free the file descriptor table and any file descriptors that are still open */
  fdt_destroy(&cur->pcb->fdt);

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;
  free(pcb_to_free);

  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create(); // This returns a pointer to NULL?
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  // Copy file_name so const is not violated
  char* file_name_copy = malloc(strlen(file_name) + 1);
  if (file_name_copy == NULL)
    goto done;
  memcpy(file_name_copy, file_name, strlen(file_name) + 1);
  char* saveptr = NULL;
  char* executable_name = strtok_r(file_name_copy, " ", &saveptr);
  // HACK replace thread name with executable name
  // TODO replace this with something better
  strlcpy(t->name, executable_name, sizeof t->name);
  strlcpy(t->pcb->process_name, executable_name, sizeof t->name);

  /* Open executable file. */
  file = filesys_open(executable_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", executable_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", executable_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  // ADD ARGUMENTS TO STACK
  // See https://cs162.org/static/proj/pintos-docs/docs/userprog/program-startup/
  char** tokens[MAX_ARGS]; // Max tokens
  char* token = executable_name;
  int argc = 0;
  do {
    *esp = *esp - strlen(token) * sizeof(char) - 1;
    memcpy(*esp, token, strlen(token) + 1);
    tokens[argc] = *esp;
    ++argc;
  } while ((token = strtok_r(NULL, " ", &saveptr)) != NULL);

  // Stack align until esp + 4 * argc - 12 is divisible by 16
  // zero pad = (esp + 4 * argc - 12) % 16
  *esp = *esp - ((uint32_t)*esp - sizeof(argc) * argc - 12) % 16;

  // Push null ptr to stack
  *esp = *esp - sizeof(NULL);
  memset(*esp, 0, sizeof(NULL));

  // Push args to the stack in descending order
  for (int i = argc - 1; i >= 0; --i) {
    *esp = *esp - sizeof(tokens[i]);
    memcpy(*esp, &tokens[i], sizeof(tokens[i]));
  }

  // Push argv** to the stack
  void* argv = *esp;
  *esp = *esp - sizeof(argv);
  memcpy(*esp, &argv, sizeof(argv));

  // Push argc to the stack
  *esp = *esp - sizeof(argc);
  memcpy(*esp, &argc, sizeof(argc));

  // Push the dummy (null) resturn address to the stack
  *esp = *esp - sizeof(NULL);
  memset(*esp, 0, sizeof(NULL));

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  free(file_name_copy);
  file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void) UNUSED, void** esp) {
  struct thread* t = thread_current();

  // 1. Allocates a new page in user memory for the stack
  void* kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage == NULL)
    return false;
  // 2. Install the page at ((uint8_t*)PHYS_BASE) - PGSIZE * NUM_THREADS * PAGES_PER_THREAD
  //     1. Each thread initially gets one page of memory (hack, can change depending on if this works?)
  //     2. NUM_THREADS can be determined dynamically based on the length of the thread list in the PCB minus 1
  int i = 1;
  bool page_allocated = false;
  void* upage;
  while (!page_allocated) {
    // upage defines the ___ of the page
    upage = (void*)PHYS_BASE - i * PGSIZE;
    // Check if the page is already allocated (pagedir_get_page returns NULL if not allocated)
    if (!pagedir_get_page(thread_current()->pcb->pagedir, upage)) {
      // If the page is not already allocated, install the page for the new stack here
      if (!pagedir_set_page(thread_current()->pcb->pagedir, upage, kpage, true)) {
        palloc_free_page(kpage);
        return false;
      }
      t->upage = upage;
      page_allocated = true;
    }
    ++i;
  }
  // 3. Set esp to the top of the newly allocated userpage page
  *esp = upage + PGSIZE - 1; // add page size so we are at the top of the page
  // 5. Idk what to do with EIP
  // 6. returns true if success else false
  return true;
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) {
  // initialize thread_tid shared_data struct
  struct shared_data* thread_shared_data = initialize_shared_data(thread_current()->tid);
  // Call thread_create(file_name, PRI_DEFAULT, start_pthread, start_pthread_args) to get a new thread ID
  void* start_pthread_args[5];
  start_pthread_args[0] = sf;
  start_pthread_args[1] = tf;
  start_pthread_args[2] = arg;
  start_pthread_args[3] = thread_shared_data;
  start_pthread_args[4] = thread_current()->pcb;
  // Create a new kernel thread which will call start_pthread
  tid_t tid = thread_create("pthread", PRI_DEFAULT, start_pthread, start_pthread_args);
  // Wait on thread_tid to verify the thread start successfully
  if (wait_for_data(thread_shared_data)) {
    return tid;
  }
  return TID_ERROR;
  // Returns TID or TID_ERROR
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void** args) {

  // 1. Takes in the parent pcb, function to execute, and its arguments
  // TODO clean this up
  stub_fun sf = args[0];
  pthread_fun tf = args[1];
  void* arg = args[2];
  struct shared_data* thread_shared_data = args[3];
  struct process* parent_pcb = args[4];
  struct thread* t = thread_current();
  t->pcb = parent_pcb;
  process_activate();

  lock_acquire(&thread_current()->pcb->kernel_lock);

  // 5. Allocates new thread_list_elem
  struct thread_list_elem* new_thread_elem = malloc(sizeof(struct thread_list_elem));
  if (new_thread_elem == NULL) {
    save_data(thread_shared_data, 0);
    free(new_thread_elem);
    return;
  }
  new_thread_elem->tid = t->tid;
  new_thread_elem->exit_status = initialize_shared_data(thread_current()->tid);

  // 6. Adds the new thread to the list of threads in the PCB
  // TODO figure out why this segfaults
  list_push_back(&thread_current()->pcb->thread_list, &new_thread_elem->elem);

  // Calls setup_thread to allocated user memory on for the stack
  struct intr_frame if_;
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  if (!setup_thread(&if_.eip, &if_.esp)) {
    save_data(thread_shared_data, 0);
    free(new_thread_elem);
    lock_release(&thread_current()->pcb->kernel_lock);
    return;
  }

  // 8. Sets esp to the address of the return address
  // 3. Places function args onto the top of the allocated stack
  // ADD ARGUMENTS TO STACK
  // See https://cs162.org/static/proj/pintos-docs/docs/userprog/program-startup/

  // Push the arg to the stack
  if_.esp -= sizeof(void*);
  memcpy(if_.esp, &arg, sizeof(void*));

  // Push the function pointer to the stack
  if_.esp -= sizeof(void*);
  memcpy(if_.esp, &tf, sizeof(void*));

  // 4. Set the return address to NULL
  // Push the dummy (null) return address to the stack
  if_.esp -= sizeof(void*);
  memset(if_.esp, 0, sizeof(NULL));

  // 9. Sets eip to the start of the function
  if_.eip = sf;

  // Set shared data value to 1 if successful, 0 if not
  save_data(thread_shared_data, 1);

  // 10. Simulates return from interrupt similar to in start_process
  lock_release(&thread_current()->pcb->kernel_lock);
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid UNUSED) {
  lock_acquire(&thread_current()->pcb->kernel_lock);
  // Verify it is not being called on itself
  if (tid == thread_current()->tid) {
    return TID_ERROR;
  }
  //  TODO If a thread joins on main, it should be woken up and allowed to run after main calls pthread_exit but before the process is killed (see above).
  struct list_elem* e;
  for (e = list_begin(&thread_current()->pcb->thread_list);
       e != list_end(&thread_current()->pcb->thread_list); e = list_next(e)) {
    struct thread_list_elem* thread_elem = list_entry(e, struct thread_list_elem, elem);
    if (thread_elem->tid == tid) {
      // TODO Must drop locks to prevent a deadlock
      lock_release(&thread_current()->pcb->kernel_lock);
      wait_for_data(thread_elem->exit_status);
      lock_acquire(&thread_current()->pcb->kernel_lock);
      // acquire locks again
      list_remove(e);
      lock_release(&thread_current()->pcb->kernel_lock);
      return tid;
    }
  }
  lock_release(&thread_current()->pcb->kernel_lock);
  return TID_ERROR;
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */

void pthread_exit(void) {
  lock_acquire(&thread_current()->pcb->kernel_lock);
  struct thread* cur = thread_current();

  // Free the thread's userspace stack
  void* upage = cur->upage;
  if (upage != NULL) {
    uint32_t* pd = cur->pcb->pagedir;
    pagedir_clear_page(pd, upage);
  }

  // Populate exit status
  for (struct list_elem* e = list_begin(&thread_current()->pcb->thread_list);
       e != list_end(&thread_current()->pcb->thread_list); e = list_next(e)) {
    struct thread_list_elem* thread_elem = list_entry(e, struct thread_list_elem, elem);
    if (thread_elem->tid == cur->tid) {
      save_data(thread_elem->exit_status, 0);
      break;
    }
  }

  // Exit the thread
  lock_release(&thread_current()->pcb->kernel_lock);
  thread_exit();
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {
  lock_acquire(&thread_current()->pcb->kernel_lock);
  struct thread* curr = thread_current();

  for (struct list_elem* e = list_begin(&thread_current()->pcb->thread_list);
       e != list_end(&thread_current()->pcb->thread_list); e = list_next(e)) {
    struct thread_list_elem* thread_elem = list_entry(e, struct thread_list_elem, elem);
    if (thread_elem->tid == curr->tid) {
      save_data(thread_elem->exit_status, 0);
      break;
    }
  }

  for (struct list_elem* e = list_begin(&thread_current()->pcb->thread_list);
       e != list_end(&thread_current()->pcb->thread_list); e = list_next(e)) {
    struct thread_list_elem* thread_elem = list_entry(e, struct thread_list_elem, elem);
    if (thread_elem->tid != curr->tid) {
      lock_release(&thread_current()->pcb->kernel_lock);
      pthread_join(thread_elem->tid);
      lock_acquire(&thread_current()->pcb->kernel_lock);
    }
  }

  void* upage = curr->upage;
  if (upage != NULL) {
    uint32_t* pd = curr->pcb->pagedir;
    pagedir_clear_page(pd, upage);
  }

  lock_release(&thread_current()->pcb->kernel_lock);
  process_exit(0);
}
