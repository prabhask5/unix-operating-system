#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define LAST_DIRECT_POINTER_INDEX 119
#define LAST_INDIRECT_POINTER_INDEX 2
#define LAST_DOUBLY_INDIRECT_POINTER_INDEX 1
#define LAST_CHILD_BLOCK_POINTER_INDEX 127

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t start; /* First data sector. */
  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
  bool is_dir;
  block_sector_t direct_pointers[LAST_DIRECT_POINTER_INDEX + 1];
  block_sector_t indirect_pointers[LAST_INDIRECT_POINTER_INDEX + 1];
  block_sector_t doubly_indirect_pointers[LAST_DOUBLY_INDIRECT_POINTER_INDEX + 1];
};

struct indirect_block {
  block_sector_t children[128];
};

struct cache_block {
  block_sector_t sector;
  uint8_t* data; // buffer of size BLOCK_SECTOR_SIZE
  bool is_dirty;
  bool is_accessed;
  bool is_valid;
  struct lock block_lock;
};

static struct cache_block* cache[64];
static size_t cache_size;
static struct lock cache_lock;
static size_t clock_arm;
static size_t cache_hit_count;
static size_t cache_miss_count;

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct lock inode_lock; /* Lock for inode */
  struct lock metadata_lock;
  struct lock deny_writes_lock;
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static int byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  struct inode_disk* disk_node = malloc(BLOCK_SECTOR_SIZE);
  if (disk_node == NULL)
    return -1;

  block_read(fs_device, inode->sector, (void*)disk_node);

  int blocks;
  if (disk_node->length == 0)
    blocks = 0;
  else
    blocks = (disk_node->length - 1) / BLOCK_SECTOR_SIZE + 1;
  int blocks_needed = pos / BLOCK_SECTOR_SIZE + 1;

  if (pos < 0 || blocks_needed > blocks) {
    free(disk_node);
    return -1;
  }

  off_t direct_block_offset_boundary = 120 * BLOCK_SECTOR_SIZE;
  off_t indirect_block_offset_boundary = direct_block_offset_boundary + 3 * 128 * BLOCK_SECTOR_SIZE;
  off_t doubly_indirect_block_offset_boundary =
      indirect_block_offset_boundary + 3 * 128 * 128 * BLOCK_SECTOR_SIZE;

  if (pos < direct_block_offset_boundary) {
    int direct_block_num = pos / BLOCK_SECTOR_SIZE;

    block_sector_t ret_sector = disk_node->direct_pointers[direct_block_num];
    free(disk_node);
    return ret_sector;
  }

  if (pos < indirect_block_offset_boundary) {
    off_t normalized_pos = pos - direct_block_offset_boundary;
    int indirect_block_num = normalized_pos / (128 * BLOCK_SECTOR_SIZE);

    struct indirect_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);
    if (indirect_block == NULL) {
      free(disk_node);
      return -1;
    }

    block_read(fs_device, disk_node->indirect_pointers[indirect_block_num], (void*)indirect_block);
    free(disk_node);

    normalized_pos -= 128 * BLOCK_SECTOR_SIZE * indirect_block_num;
    int direct_block_num = normalized_pos / BLOCK_SECTOR_SIZE;

    block_sector_t ret_sector = indirect_block->children[direct_block_num];
    free(indirect_block);
    return ret_sector;
  }

  if (pos < doubly_indirect_block_offset_boundary) {
    off_t normalized_pos = pos - indirect_block_offset_boundary;
    int doubly_indirect_block_num = normalized_pos / (128 * 128 * BLOCK_SECTOR_SIZE);

    struct indirect_block* doubly_indirect_block = malloc(BLOCK_SECTOR_SIZE);
    if (doubly_indirect_block == NULL) {
      free(disk_node);
      return -1;
    }

    block_read(fs_device, disk_node->doubly_indirect_pointers[doubly_indirect_block_num],
               (void*)doubly_indirect_block);
    free(disk_node);

    normalized_pos -= 128 * 128 * BLOCK_SECTOR_SIZE * doubly_indirect_block_num;
    int indirect_block_num = normalized_pos / (128 * BLOCK_SECTOR_SIZE);

    struct indirect_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);
    if (indirect_block == NULL) {
      free(doubly_indirect_block);
      return -1;
    }

    block_read(fs_device, doubly_indirect_block->children[indirect_block_num],
               (void*)indirect_block);
    free(doubly_indirect_block);

    normalized_pos -= 128 * BLOCK_SECTOR_SIZE * indirect_block_num;
    int direct_block_num = normalized_pos / BLOCK_SECTOR_SIZE;

    block_sector_t ret_sector = indirect_block->children[direct_block_num];
    free(indirect_block);
    return ret_sector;
  }
}

static void zero_block(block_sector_t sector) {
  uint8_t* zeros = malloc(BLOCK_SECTOR_SIZE);
  memset(zeros, 0, BLOCK_SECTOR_SIZE);
  block_write(fs_device, sector, (void*)zeros);
  free(zeros);
}

static int resize(block_sector_t inode_sector, size_t num_blocks) {
  ASSERT(num_blocks > 0);

  struct inode_disk* disk_node = malloc(BLOCK_SECTOR_SIZE);
  if (disk_node == NULL)
    return -1;

  block_read(fs_device, inode_sector, (void*)disk_node);

  off_t direct_block_offset_boundary = 120 * BLOCK_SECTOR_SIZE;
  off_t indirect_block_offset_boundary = direct_block_offset_boundary + 3 * 128 * BLOCK_SECTOR_SIZE;
  off_t doubly_indirect_block_offset_boundary =
      indirect_block_offset_boundary + 3 * 128 * 128 * BLOCK_SECTOR_SIZE;

  int last_db = -1;
  int last_idb = -1;
  int last_didb = -1;
  int last_pos = disk_node->length - 1;

  if (last_pos >= 0 && last_pos < direct_block_offset_boundary) {
    last_db = last_pos / BLOCK_SECTOR_SIZE;

  } else if (last_pos >= 0 && last_pos < indirect_block_offset_boundary) {
    off_t normalized_pos = last_pos - direct_block_offset_boundary;
    last_idb = normalized_pos / (128 * BLOCK_SECTOR_SIZE);

    normalized_pos -= 128 * BLOCK_SECTOR_SIZE * last_idb;
    last_db = normalized_pos / BLOCK_SECTOR_SIZE;

  } else if (last_pos >= 0 && last_pos < doubly_indirect_block_offset_boundary) {
    off_t normalized_pos = last_pos - indirect_block_offset_boundary;
    last_didb = normalized_pos / (128 * 128 * BLOCK_SECTOR_SIZE);

    normalized_pos -= 128 * 128 * BLOCK_SECTOR_SIZE * last_didb;
    last_idb = normalized_pos / (128 * BLOCK_SECTOR_SIZE);

    normalized_pos -= 128 * BLOCK_SECTOR_SIZE * last_idb;
    last_db = normalized_pos / BLOCK_SECTOR_SIZE;
  }

  block_sector_t ret_sector;

  for (int i = 0; i < num_blocks; i++) {
    if (last_didb >= 0) {
      bool success = true;
      struct indirect_block* doubly_indirect_block = NULL;
      struct indirect_block* indirect_block = NULL;

      if (last_didb == LAST_DOUBLY_INDIRECT_POINTER_INDEX &&
          last_idb == LAST_CHILD_BLOCK_POINTER_INDEX &&
          last_db == LAST_CHILD_BLOCK_POINTER_INDEX) { // special case: we ran out of space, too bad
        free(disk_node);
        return -1;
      } else if (
          last_idb == LAST_CHILD_BLOCK_POINTER_INDEX &&
          last_db ==
              LAST_CHILD_BLOCK_POINTER_INDEX) { // general special case: since last allocated indirect block is the last one in this doubly indirect block, we move to the next doubly indirect block
        bool new_doubly_indirect_allocation_success =
            free_map_allocate(1, &disk_node->doubly_indirect_pointers[last_didb + 1]);
        success = success && new_doubly_indirect_allocation_success;
        doubly_indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
        bool dib_malloc_success = doubly_indirect_block != NULL;
        success = success && doubly_indirect_block != NULL;
        bool ib_malloc_success = false;
        bool new_indirect_allocation_success = false;
        bool new_direct_allocation_success = false;

        if (success) {
          new_indirect_allocation_success =
              free_map_allocate(1, &doubly_indirect_block->children[0]);
          success = success && new_indirect_allocation_success;
          indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
          ib_malloc_success = indirect_block != NULL;
          success = success && indirect_block != NULL;
        }

        if (success) {
          new_direct_allocation_success = free_map_allocate(1, &indirect_block->children[0]);
          success = success && new_direct_allocation_success;
        }

        if (!success) {
          if (new_doubly_indirect_allocation_success)
            free_map_release(disk_node->doubly_indirect_pointers[last_didb + 1], 1);
          if (new_indirect_allocation_success)
            free_map_release(doubly_indirect_block->children[0], 1);
          if (new_direct_allocation_success)
            free_map_release(indirect_block->children[0], 1);
          if (dib_malloc_success)
            free(doubly_indirect_block);
          if (ib_malloc_success)
            free(indirect_block);
          free(disk_node);
          return -1;
        }

        ret_sector = indirect_block->children[0];
        zero_block(ret_sector);
        block_write(fs_device, doubly_indirect_block->children[0], (void*)indirect_block);
        block_write(fs_device, disk_node->doubly_indirect_pointers[last_didb + 1],
                    (void*)doubly_indirect_block);
        block_write(fs_device, inode_sector, (void*)disk_node);

        last_didb++;
        last_idb = 0;
        last_db = 0;
      } else if (
          last_db ==
          LAST_CHILD_BLOCK_POINTER_INDEX) { // special general case: since last allocated direct block is the last one in this indirect block, we move to the next indirect block
        doubly_indirect_block = malloc(BLOCK_SECTOR_SIZE);
        bool dib_malloc_success = doubly_indirect_block != NULL;
        success = success && doubly_indirect_block != NULL;
        bool ib_malloc_success = false;
        bool new_indirect_allocation_success = false;
        bool new_direct_allocation_success = false;

        if (success) {
          block_read(fs_device, disk_node->doubly_indirect_pointers[last_didb],
                     (void*)doubly_indirect_block);
          new_indirect_allocation_success =
              free_map_allocate(1, &doubly_indirect_block->children[last_idb + 1]);
          success = success && new_indirect_allocation_success;
          indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
          ib_malloc_success = indirect_block != NULL;
          success = success && indirect_block != NULL;
        }

        if (success) {
          new_direct_allocation_success = free_map_allocate(1, &indirect_block->children[0]);
          success = success && new_direct_allocation_success;
        }

        if (!success) {
          if (new_indirect_allocation_success)
            free_map_release(doubly_indirect_block->children[last_idb + 1], 1);
          if (new_direct_allocation_success)
            free_map_release(indirect_block->children[0], 1);
          if (dib_malloc_success)
            free(doubly_indirect_block);
          if (ib_malloc_success)
            free(indirect_block);
          free(disk_node);
          return -1;
        }

        ret_sector = indirect_block->children[0];
        zero_block(ret_sector);
        block_write(fs_device, doubly_indirect_block->children[last_idb + 1],
                    (void*)indirect_block);
        block_write(fs_device, disk_node->doubly_indirect_pointers[last_didb],
                    (void*)doubly_indirect_block);

        last_idb++;
        last_db = 0;
      } else { // general case: we just allocate the next direct block
        doubly_indirect_block = malloc(BLOCK_SECTOR_SIZE);
        indirect_block = malloc(BLOCK_SECTOR_SIZE);
        bool dib_malloc_success = doubly_indirect_block != NULL;
        bool ib_malloc_success = indirect_block != NULL;
        success = success && doubly_indirect_block != NULL && indirect_block != NULL;
        bool new_direct_allocation_success = false;

        if (success) {
          smart_block_read(disk_node->doubly_indirect_pointers[last_didb],
                           (void*)doubly_indirect_block);
          smart_block_read(doubly_indirect_block->children[last_idb], (void*)indirect_block);
          new_direct_allocation_success =
              free_map_allocate(1, &indirect_block->children[last_db + 1]);
          success = success && new_direct_allocation_success;
        }

        if (!success) {
          if (new_direct_allocation_success)
            free_map_release(indirect_block->children[last_db + 1], 1);
          if (dib_malloc_success)
            free(doubly_indirect_block);
          if (ib_malloc_success)
            free(indirect_block);
          free(disk_node);
          return -1;
        }

        ret_sector = indirect_block->children[last_db + 1];
        zero_block(ret_sector);
        block_write(fs_device, doubly_indirect_block->children[last_idb], (void*)indirect_block);

        last_db++;
      }

      free(indirect_block);
      free(doubly_indirect_block);
    } else if (last_idb >= 0) {
      bool success = true;
      struct indirect_block* indirect_block = NULL;

      if (last_idb == LAST_INDIRECT_POINTER_INDEX &&
          last_db ==
              LAST_CHILD_BLOCK_POINTER_INDEX) { // special case: since last allocated indirect & direct block is the last one, we know need to allocate a doubly indirect block
        bool new_doubly_indirect_allocation_success =
            free_map_allocate(1, &disk_node->doubly_indirect_pointers[0]);
        success = success && new_doubly_indirect_allocation_success;
        struct indirect_block* doubly_indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
        bool dib_malloc_success = doubly_indirect_block != NULL;
        success = success && doubly_indirect_block != NULL;
        bool ib_malloc_success = false;
        bool new_indirect_allocation_success = false;
        bool new_direct_allocation_success = false;

        if (success) {
          new_indirect_allocation_success =
              free_map_allocate(1, &doubly_indirect_block->children[0]);
          success = success && new_indirect_allocation_success;
          indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
          ib_malloc_success = indirect_block != NULL;
          success = success && indirect_block != NULL;
        }

        if (success) {
          new_direct_allocation_success = free_map_allocate(1, &indirect_block->children[0]);
          success = success && new_direct_allocation_success;
        }

        if (!success) {
          if (new_doubly_indirect_allocation_success)
            free_map_release(disk_node->doubly_indirect_pointers[0], 1);
          if (new_indirect_allocation_success)
            free_map_release(doubly_indirect_block->children[0], 1);
          if (new_direct_allocation_success)
            free_map_release(indirect_block->children[0], 1);
          if (dib_malloc_success)
            free(doubly_indirect_block);
          if (ib_malloc_success)
            free(indirect_block);
          free(disk_node);
          return -1;
        }

        ret_sector = indirect_block->children[0];
        zero_block(ret_sector);
        block_write(fs_device, doubly_indirect_block->children[0], (void*)indirect_block);
        block_write(fs_device, disk_node->doubly_indirect_pointers[0],
                    (void*)doubly_indirect_block);
        block_write(fs_device, inode_sector, (void*)disk_node);

        last_didb = 0;
        last_idb = 0;
        last_db = 0;
      } else if (
          last_db ==
          LAST_CHILD_BLOCK_POINTER_INDEX) { // special general case: since last allocated direct block is the last one in this indirect block, we move to the next indirect block
        bool new_indirect_allocation_success =
            free_map_allocate(1, &disk_node->indirect_pointers[last_idb + 1]);
        success = success && new_indirect_allocation_success;
        indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
        bool malloc_success = indirect_block != NULL;
        success = success && indirect_block != NULL;
        bool new_direct_allocation_success = false;

        if (success) {
          new_direct_allocation_success = free_map_allocate(1, &indirect_block->children[0]);
          success = success && new_direct_allocation_success;
        }

        if (!success) {
          if (new_indirect_allocation_success)
            free_map_release(disk_node->indirect_pointers[last_idb + 1], 1);
          if (new_direct_allocation_success)
            free_map_release(indirect_block->children[0], 1);
          if (malloc_success)
            free(indirect_block);
          free(disk_node);
          return -1;
        }

        ret_sector = indirect_block->children[0];
        zero_block(ret_sector);
        block_write(fs_device, disk_node->indirect_pointers[last_idb + 1], (void*)indirect_block);
        block_write(fs_device, inode_sector, (void*)disk_node);

        last_idb++;
        last_db = 0;
      } else { // general case: we just allocate the next direct block
        indirect_block = malloc(BLOCK_SECTOR_SIZE);
        bool malloc_success = indirect_block != NULL;
        success = indirect_block != NULL;
        bool new_direct_allocation_success = false;

        if (success) {
          smart_block_read(disk_node->indirect_pointers[last_idb], (void*)indirect_block);
          new_direct_allocation_success =
              free_map_allocate(1, &indirect_block->children[last_db + 1]);
          success = success && new_direct_allocation_success;
        }

        if (!success) {
          if (new_direct_allocation_success)
            free_map_release(indirect_block->children[last_db + 1], 1);
          if (malloc_success)
            free(indirect_block);
          free(disk_node);
          return -1;
        }

        ret_sector = indirect_block->children[last_db + 1];
        zero_block(ret_sector);
        block_write(fs_device, disk_node->indirect_pointers[last_idb], (void*)indirect_block);

        last_db++;
      }

      free(indirect_block);
    } else {
      bool success = true;

      if (last_db ==
          LAST_DIRECT_POINTER_INDEX) { // special case: since last allocated direct block is the last one, we now need to allocate an indirect block
        bool new_indirect_allocation_success =
            free_map_allocate(1, &disk_node->indirect_pointers[0]);
        success = new_indirect_allocation_success;
        struct indirect_block* indirect_block = calloc(1, BLOCK_SECTOR_SIZE);
        bool malloc_success = indirect_block != NULL;
        success = success && indirect_block != NULL;
        bool new_direct_allocation_success = false;

        if (success) {
          new_direct_allocation_success = free_map_allocate(1, &indirect_block->children[0]);
          success = success && new_direct_allocation_success;
        }

        if (!success) {
          if (new_indirect_allocation_success)
            free_map_release(disk_node->indirect_pointers[0], 1);
          if (new_direct_allocation_success)
            free_map_release(indirect_block->children[0], 1);
          if (malloc_success)
            free(indirect_block);
          free(disk_node);
          return -1;
        }

        ret_sector = indirect_block->children[0];
        zero_block(ret_sector);
        block_write(fs_device, disk_node->indirect_pointers[0], (void*)indirect_block);
        free(indirect_block);

        last_idb = 0;
        last_db = 0;
      } else { // general case: we just allocate the next direct block
        if (!free_map_allocate(1, &disk_node->direct_pointers[last_db + 1])) {
          free(disk_node);
          return -1;
        }
        ret_sector = disk_node->direct_pointers[last_db + 1];
        zero_block(ret_sector);
        last_db++;
      }
    }
  }

  block_write(fs_device, inode_sector, (void*)disk_node);
  free(disk_node);
  return ret_sector;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
static struct lock open_inodes_lock;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  lock_init(&open_inodes_lock);

  lock_init(&cache_lock);
  clock_arm = 0;
  cache_size = 0;
  cache_hit_count = 0;
  cache_miss_count = 0;

  for (int i = 0; i < 64; i++) {
    cache[i] = malloc(sizeof(struct cache_block));
    if (cache[i] == NULL)
      return;

    lock_init(&cache[i]->block_lock);
    cache[i]->is_dirty = false;
    cache[i]->is_accessed = false;
    cache[i]->is_valid = false;
  }
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, bool is_dir) {
  struct inode_disk* disk_inode = NULL;

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode == NULL)
    return false;

  disk_inode->magic = INODE_MAGIC;
  block_write(fs_device, sector, disk_inode);

  size_t num_blocks = bytes_to_sectors(length);
  if (num_blocks > 0) {
    if (resize(sector, num_blocks) == -1)
      return false;
    block_read(fs_device, sector, disk_inode);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    disk_inode->is_dir = is_dir;
    if (free_map_allocate(sectors, &disk_inode->start)) {
      block_write(fs_device, sector, disk_inode);
      if (sectors > 0) {
        static char zeros[BLOCK_SECTOR_SIZE];
        size_t i;

        for (i = 0; i < sectors; i++)
          block_write(fs_device, disk_inode->start + i, zeros);
      }
      success = true;
    }
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  lock_acquire(&open_inodes_lock);
  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      lock_release(&open_inodes_lock);
      return inode;
    }
  }
  lock_release(&open_inodes_lock);

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  lock_acquire(&open_inodes_lock);
  list_push_front(&open_inodes, &inode->elem);
  lock_release(&open_inodes_lock);

  /* Initialize. */
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  
  lock_init(&inode->inode_lock);
  lock_init(&inode->metadata_lock);
  lock_init(&inode->deny_writes_lock);
  
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL) {
    lock_acquire(&inode->metadata_lock);
    inode->open_cnt++;
    lock_release(&inode->metadata_lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  lock_acquire(&inode->metadata_lock);
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      lock_release(&inode->metadata_lock);

      struct inode_disk* disk_node = malloc(BLOCK_SECTOR_SIZE);
      if (disk_node == NULL) {
        free(inode);
        return;
      }

      block_read(fs_device, inode->sector, (void*)disk_node);
      off_t bytes_remaining = disk_node->length;

      int direct_block_num = 0;
      int indirect_block_num = 0;
      int doubly_indirect_block_num = 0;

      while (bytes_remaining > 0 && direct_block_num <= LAST_DIRECT_POINTER_INDEX) {
        free_map_release(disk_node->direct_pointers[direct_block_num], 1);

        if (bytes_remaining >= BLOCK_SECTOR_SIZE)
          bytes_remaining -= BLOCK_SECTOR_SIZE;
        else
          bytes_remaining = 0;
        direct_block_num++;
      }

      while (bytes_remaining > 0 && indirect_block_num <= LAST_INDIRECT_POINTER_INDEX) {
        struct indirect_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);
        if (indirect_block == NULL) {
          free(disk_node);
          free(inode);
          return;
        }

        block_read(fs_device, disk_node->indirect_pointers[indirect_block_num],
                   (void*)indirect_block);

        direct_block_num = 0;
        while (bytes_remaining > 0 && direct_block_num <= LAST_CHILD_BLOCK_POINTER_INDEX) {
          free_map_release(indirect_block->children[direct_block_num], 1);

          if (bytes_remaining >= BLOCK_SECTOR_SIZE)
            bytes_remaining -= BLOCK_SECTOR_SIZE;
          else
            bytes_remaining = 0;
          direct_block_num++;
        }

        free(indirect_block);
        free_map_release(disk_node->indirect_pointers[indirect_block_num], 1);
        indirect_block++;
      }

      while (bytes_remaining > 0 &&
             doubly_indirect_block_num <= LAST_DOUBLY_INDIRECT_POINTER_INDEX) {
        struct indirect_block* doubly_indirect_block = malloc(BLOCK_SECTOR_SIZE);
        if (doubly_indirect_block == NULL) {
          free(disk_node);
          free(inode);
          return;
        }

        block_read(fs_device, disk_node->doubly_indirect_pointers[doubly_indirect_block_num],
                   (void*)doubly_indirect_block);

        indirect_block_num = 0;
        while (bytes_remaining > 0 && indirect_block_num <= LAST_CHILD_BLOCK_POINTER_INDEX) {
          struct indirect_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);
          if (indirect_block == NULL) {
            free(doubly_indirect_block);
            free(disk_node);
            free(inode);
            return;
          }

          block_read(fs_device, doubly_indirect_block->children[indirect_block_num],
                     (void*)indirect_block);

          direct_block_num = 0;
          while (bytes_remaining > 0 && direct_block_num <= LAST_CHILD_BLOCK_POINTER_INDEX) {
            free_map_release(indirect_block->children[direct_block_num], 1);

            if (bytes_remaining >= BLOCK_SECTOR_SIZE)
              bytes_remaining -= BLOCK_SECTOR_SIZE;
            else
              bytes_remaining = 0;
            direct_block_num++;
          }

          free(indirect_block);
          free_map_release(doubly_indirect_block->children[indirect_block_num], 1);
          indirect_block++;
        }

        free(doubly_indirect_block);
        free_map_release(disk_node->doubly_indirect_pointers[doubly_indirect_block_num], 1);
        doubly_indirect_block++;
      }

      free_map_release(inode->sector, 1);
      free(disk_node);
    } else {
      lock_release(&inode->metadata_lock);
    }

    free(inode);
  } else {
    lock_release(&inode->metadata_lock);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  lock_acquire(&inode->metadata_lock);
  inode->removed = true;
  lock_release(&inode->metadata_lock);
}

/* Resize file by "num_blocks" blocks by allocating one in inode tree, also zeros out new block before use, return the last block allocated since this is the block we are writing to at the offset */
static int inode_resize(struct inode* inode, size_t num_blocks) {
  lock_acquire(&inode->inode_lock);
  block_sector_t ret_sector = resize(inode->sector, num_blocks);
  lock_release(&inode->inode_lock);
  return ret_sector;
}

static void set_file_length(struct inode* inode, off_t new_length) {
  struct inode_disk* disk_node = malloc(BLOCK_SECTOR_SIZE);
  if (disk_node == NULL)
    return;

  block_read(fs_device, inode->sector, (void*)disk_node);
  disk_node->length = new_length;

  block_write(fs_device, inode->sector, (void*)disk_node);
  free(disk_node);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx;
    int res = byte_to_sector(inode, offset);
    if (res == -1)
      break;
    else
      sector_idx = (block_sector_t)res;

    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      smart_block_read(sector_idx, buffer + bytes_read);
    } else {
      smart_read(sector_idx, buffer + bytes_read, sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs. */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;

  lock_acquire(&inode->deny_writes_lock);
  if (inode->deny_write_cnt) {
    lock_release(&inode->deny_writes_lock);
    return 0;
  }

  while (size > 0) {
    off_t length = inode_length(inode);

    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx;
    int res = byte_to_sector(inode, offset);
    if (res == -1) {
      int blocks;
      if (length == 0)
        blocks = 0;
      else
        blocks = (length - 1) / BLOCK_SECTOR_SIZE + 1;
      int blocks_needed = offset / BLOCK_SECTOR_SIZE + 1;

      size_t num_blocks = blocks_needed - blocks;
      res = inode_resize(inode, num_blocks);

      if (res == -1)
        break;
      else
        sector_idx = (block_sector_t)res;
    } else
      sector_idx = (block_sector_t)res;

    int sector_ofs = offset % BLOCK_SECTOR_SIZE;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < sector_left ? size : sector_left;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      smart_block_write(sector_idx, buffer + bytes_written);
    } else {
      smart_write(sector_idx, buffer + bytes_written, sector_ofs, chunk_size);
    }

    if (offset + chunk_size > length)
      set_file_length(inode, offset + chunk_size);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  lock_release(&inode->deny_writes_lock);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  lock_acquire(&inode->deny_writes_lock);
  inode->deny_write_cnt++;
  lock_release(&inode->deny_writes_lock);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  lock_acquire(&inode->deny_writes_lock);
  inode->deny_write_cnt--;
  lock_release(&inode->deny_writes_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }

/* Checks if the inode is a directory */
bool inode_is_dir(const struct inode* inode) {
  ASSERT(inode != NULL);
  return inode->data.is_dir;
}
