#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "userprog/process.h"
/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { free_map_close(); }

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  block_sector_t inode_sector = 0;
  struct dir* dir = NULL;
  char final_name[NAME_MAX + 1];

  if (!parse_path(name, &dir, final_name)) {
    return false;
  }

  // char* slash_pos = strrchr(name, '/');
  // if (slash_pos != NULL) {
  //   dir = path_to_dir(name);
  //   name = slash_pos + 1;
  // } else if (thread_current()->cwd != NULL) {
  //   dir = dir_reopen(thread_current()->cwd);
  // }

  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size, false) &&
                  dir_add(dir, final_name, inode_sector, false));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {

  // struct dir* dir;

  // if (!thread_current()->pcb->cwd) {
  //   dir = dir_open_root();
  // } else {
  //   dir = dir_reopen(thread_current()->pcb->cwd);
  // }

  struct dir* dir = NULL;
  char final_name[NAME_MAX + 1];

  if (!parse_path(name, &dir, final_name)) {
    return false;
  }

  struct inode* inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, name, &inode);
  // dir_close(dir);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  struct dir* dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

bool filesys_mkdir(const char* path) {
  block_sector_t inode_sector = 0;
  struct dir* dir = NULL;
  char final_name[NAME_MAX + 1];

  if (!parse_path(path, &dir, final_name)) {
    return false;
  }

  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  dir_create(inode_sector, 1024) && dir_add(dir, final_name, inode_sector, true));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

bool filesys_chdir(const char* name) {
  struct dir* dir = NULL;
  char final_name[NAME_MAX + 1];

  if (!parse_path(name, &dir, final_name)) {
    return false;
  }

  thread_current()->pcb->cwd = dir;

  return true;
}