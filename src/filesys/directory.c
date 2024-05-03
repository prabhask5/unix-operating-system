#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "../threads/thread.h"
#include "userprog/process.h"

/* A directory. */
struct dir {
  struct inode* inode; /* Backing store. */
  off_t pos;           /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create(block_sector_t sector, size_t entry_cnt) {
  if (!inode_create(sector, entry_cnt * sizeof(struct dir_entry), true)) {
    return false;
  }

  struct dir* dir = dir_open(inode_open(sector));
  if (!dir) {
    return false;
  }
  // .
  if (!dir_add(dir, ".", sector, true)) {
    dir_close(dir);
    return false;
  }

  // .. (points to itself atm, as root)
  if (!dir_add(dir, "..", sector, true)) {
    dir_close(dir);
    return false;
  }

  return true;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir* dir_open(struct inode* inode) {
  struct dir* dir = calloc(1, sizeof *dir);
  if (inode != NULL && dir != NULL) {
    dir->inode = inode;
    dir->pos = 0;
    return dir;
  } else {
    inode_close(inode);
    free(dir);
    return NULL;
  }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir* dir_open_root(void) {
  return dir_open(inode_open(ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir* dir_reopen(struct dir* dir) {
  return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close(struct dir* dir) {
  if (dir != NULL) {
    inode_close(dir->inode);
    free(dir);
  }
}

/* Returns the inode encapsulated by DIR. */
struct inode* dir_get_inode(struct dir* dir) {
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup(const struct dir* dir, const char* name, struct dir_entry* ep, off_t* ofsp) {
  struct dir_entry e;
  size_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (e.in_use && !strcmp(name, e.name)) {
      if (ep != NULL)
        *ep = e;
      if (ofsp != NULL)
        *ofsp = ofs;
      return true;
    }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup(const struct dir* dir, const char* name, struct inode** inode) {
  struct dir_entry e;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  if (lookup(dir, name, &e, NULL))
    *inode = inode_open(e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add(struct dir* dir, const char* name, block_sector_t inode_sector, bool is_dir) {
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen(name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup(dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy(e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

  // TODO: write something that refers back to parent

done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove(struct dir* dir, const char* name) {
  struct dir_entry e;
  struct inode* inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Find directory entry. */
  if (!lookup(dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open(e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove(inode);
  success = true;

done:
  inode_close(inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir(struct dir* dir, char name[NAME_MAX + 1]) {
  struct dir_entry e;

  while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
    dir->pos += sizeof e;
    if (e.in_use) {
      strlcpy(name, e.name, NAME_MAX + 1);
      return true;
    }
  }
  return false;
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

/*helper function to get inode given a path string. Handles 
nested paths here*/
struct inode* path_to_inode(const char* path) {
  struct dir* dir;
  struct inode* inode = NULL;
  char part[NAME_MAX + 1];
  bool success = false;

  if (path == NULL || strlen(path) == 0) {
    return NULL;
  }

  // Determine if the path is absolute or relative
  if (path[0] == '/' || !thread_current()->pcb->cwd) {
    dir = dir_open_root();
  } else {
    dir = dir_reopen(thread_current()->pcb->cwd);
  }

  if (dir == NULL) {
    return NULL;
  }

  const char* next_part = path;

  // Traverse the path part by part
  while (get_next_part(part, &next_part) == 1) {

    // Check if the directory has the next part
    if (!dir_lookup(dir, part, &inode)) {
      dir_close(dir);
      return NULL;
    }

    // if we aren't at the end
    if (*next_part != '\0') {

      // and it's a file, that's an issue
      if (!inode_is_dir(inode)) {
        inode_close(inode);
        dir_close(dir);
        return NULL;
      }

      // otherwise it's another subdir, so open it
      struct dir* next_dir = dir_open(inode);
      dir_close(dir);
      dir = next_dir;
      if (dir == NULL) {
        inode_close(inode);
        return NULL;
      }
    }
  }

  return dir;
}

/* helper, given a/b/c, it puts a pointer to a/b in dir_path, and c as a char into final name.


if any part in the dir_path doesn't exist or is not a dir, it returns false

*/

/*loop through parts. If it's not the final part, and it's either a file or not existent, return false. 

put the name of the final part inside final_name. if the final part is a dir that exists, point dir_path to it, 
otherwise dir_path should point to the dir until this last part, e.g. a/b/file should have dir path pointing to a/b


*/

// get parent dir

// get's the parent dir of the name of the file that's passed in, if the file exists

/*

input: 'a/b/c'
we're in a/b and c exists

return ptr to a/b


*/

// get dir ptr

bool parse_path(const char* path, struct dir** dir_path, char* final_name) {
  if (path == NULL || dir_path == NULL || final_name == NULL)
    return false;

  char part[NAME_MAX + 1];
  struct dir* dir;
  struct inode* inode = NULL;

  // Determine starting directory based on path or current working directory
  if (path[0] == '/' || !thread_current()->pcb->cwd)
    dir = dir_open_root();
  else
    dir = dir_reopen(thread_current()->pcb->cwd);

  if (dir == NULL)
    return false;

  const char* src = path;
  bool last_part = false;

  while (get_next_part(part, &src) == 1) {
    last_part = (*src == '\0');

    // Attempt to look up the part in the current directory
    if (!dir_lookup(dir, part, &inode)) {
      // If the part cannot be found and it's not the last part, fail
      if (!last_part) {
        dir_close(dir);
        return false;
      }
    }

    if (inode && !last_part && !inode_is_dir(inode)) {
      // If part is a file and it's not the last part, fail
      inode_close(inode);
      dir_close(dir);
      return false;
    }

    if (last_part) {
      // Handle the final part
      strlcpy(final_name, part, NAME_MAX + 1);
      *dir_path = dir; // Assign the directory correctly for the final part

      if (inode) {
        if (inode_is_dir(inode)) {
          *dir_path = dir_open(inode);
        }
      }

      return true;
    }

    // Prepare for the next iteration
    if (inode) {
      struct dir* next_dir = dir_open(inode);
      inode_close(inode);
      dir_close(dir);
      if (next_dir == NULL)
        return false;
      dir = next_dir;
    }
  }

  dir_close(dir);
  return false;
}

bool get_parent_dir(const char* path, struct dir** parent_dir) {
  if (path == NULL || parent_dir == NULL)
    return false;

  // Determine starting directory based on path or current working director
  struct dir* current_dir;
  if (path[0] == '/' || !thread_current()->pcb->cwd)
    current_dir = dir_open_root();
  else
    current_dir = dir_reopen(thread_current()->pcb->cwd);

  if (current_dir == NULL)
    return false;

  char part[NAME_MAX + 1];
  const char* src = path;
  while (get_next_part(part, &src) == 1) {

    bool is_last_part = (*src == '\0');
    if (is_last_part) {
      // Return the current directory as the parent directory
      *parent_dir = current_dir;
      return true;
    }

    // If the part cannot be found and it's not the last part, fail
    struct inode* inode = NULL;
    if (!dir_lookup(current_dir, part, &inode) || !inode_is_dir(inode)) {
      dir_close(current_dir);
      return false;
    }

    // Prepare for the next iteration
    struct dir* next_dir = dir_open(inode);
    dir_close(current_dir);
    if (next_dir == NULL)
      return false;
    current_dir = next_dir;
  }

  dir_close(current_dir);
  return false;
}

bool get_dir_from_path(const char* path, struct dir** dir_path) {

  struct dir* parent_dir = NULL;
  if (!get_parent_dir(path, &parent_dir)) {
    return false;
  }

  // Get the final name
  char name[NAME_MAX + 1];
  char* src = path;
  while (get_next_part(name, &src) == 1) {
  }

  // Get the final dir
  struct inode* inode = NULL;
  if (!dir_lookup(parent_dir, name, &inode)) {
    dir_close(parent_dir);
    return false;
  }

  if (!inode_is_dir(inode)) {
    dir_close(parent_dir);
    return false;
  }

  *dir_path = dir_open(inode);
  dir_close(parent_dir);
  return true;
}

bool dir_is_empty(struct dir* dir) {
  char name[NAME_MAX + 1];
  struct dir* subdir = dir_reopen(dir);
  while (dir_readdir(subdir, name)) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
      continue;
    }
    dir_close(subdir);
    return false;
  }
  dir_close(subdir);
  return true;
}