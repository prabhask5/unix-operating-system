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
void filesys_done(void) {
  close_cache();
  free_map_close();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* path, off_t initial_size) {
  block_sector_t inode_sector = 0;

  // Get the name of the new directory or file
  char name[NAME_MAX + 1];
  char* src = path;
  while (get_next_part(name, &src) == 1) {
  }

  // Confirm the parent exists and get the parent's directory
  struct dir* parent_dir = NULL;
  if (!get_parent_dir(path, &parent_dir))
    return false;

  // Check that the child does not exist
  struct inode* inode = NULL;
  if (dir_lookup(parent_dir, name, &inode))
    return false;

  bool success =
      (free_map_allocate(1, &inode_sector) && inode_create(inode_sector, initial_size, false) &&
       dir_add(parent_dir, name, inode_sector, false));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(parent_dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* path) {

  if (strcmp(path, "/") == 0) {
    return file_open(inode_open(ROOT_DIR_SECTOR)); // Assume ROOT_DIR_SECTOR is defined
  }

  struct dir* dir = NULL;
  if (!get_parent_dir(path, &dir)) {
    return false;
  }

  char name[NAME_MAX + 1];
  char* src = path;
  while (get_next_part(name, &src) == 1) {
  }

  struct inode* inode = NULL;

  if (!dir_lookup(dir, name, &inode)) {
    dir_close(dir);
    return NULL;
  }
  dir_close(dir);
  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* path) {

  struct dir* parent_dir = NULL;
  if (!get_parent_dir(path, &parent_dir)) {
    return false;
  }

  // Get the name of the base file
  char name[NAME_MAX + 1];
  char* src = path;
  while (get_next_part(name, &src) == 1) {
  }

  struct inode* inode = NULL;
  if (!dir_lookup(parent_dir, name, &inode)) {
    inode_close(inode);
    dir_close(parent_dir);
    return false;
  }

  // If it is a directory check to make sure its empty
  if (inode_is_dir(inode) && !dir_is_empty(inode)) {
    inode_close(inode);
    dir_close(parent_dir);
    return false;
  }

  //also that it isn't our cwd

  if (dir_is_cwd(inode)) {
    inode_close(inode);
    dir_close(parent_dir);
    return false;
  }

  inode_close(inode);
  bool success = dir_remove(parent_dir, name);
  dir_close(parent_dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16, NULL))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

bool filesys_mkdir(const char* path) {
  block_sector_t inode_sector = 0;

  // Get the name of the new directory
  char name[NAME_MAX + 1];
  char* src = path;
  while (get_next_part(name, &src) == 1) {
  }

  // Get the parent dir
  struct dir* parent_dir = NULL;
  if (!get_parent_dir(path, &parent_dir))
    return false;

  // Check that the child does not exist
  struct inode* inode = NULL;
  if (dir_lookup(parent_dir, name, &inode))
    return false;

  bool success = (free_map_allocate(1, &inode_sector) &&
                  dir_create(inode_sector, 16, inode_get_inumber(dir_get_inode(parent_dir))) &&
                  dir_add(parent_dir, name, inode_sector, true));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(parent_dir);

  return success;
}

bool filesys_chdir(const char* name) {
  if (strcmp(name, "/") == 0) {
    return file_open(inode_open(ROOT_DIR_SECTOR)); // Assume ROOT_DIR_SECTOR is defined
  }

  struct dir* dir = NULL;

  if (!get_dir_from_path(name, &dir)) {
    return false;
  }

  thread_current()->pcb->cwd = dir;

  return true;
}