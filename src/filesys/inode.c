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

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t start; /* First data sector. */
  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
  bool is_dir;
  uint32_t unused[124]; /* Not used. Changed to 124 after adding is_dir*/
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
  struct inode_disk data; /* Inode content. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);

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
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    disk_inode->is_dir = is_dir;
    if (free_map_allocate(sectors, &disk_inode->start)) {
      smart_block_write(sector, disk_inode);
      if (sectors > 0) {
        static char zeros[BLOCK_SECTOR_SIZE];
        size_t i;

        for (i = 0; i < sectors; i++)
          smart_block_write(disk_inode->start + i, zeros);
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

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  smart_block_read(inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
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

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
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
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      smart_block_write(sector_idx, buffer + bytes_written);
    } else {
      smart_write(sector_idx, buffer + bytes_written, sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }

/* Checks if the inode is a directory */
bool inode_is_dir(const struct inode* inode) {
  ASSERT(inode != NULL);
  return inode->data.is_dir;
}

void close_cache() {
  lock_acquire(&cache_lock);

  for (int i = 0; i < 64; i++) {
    struct cache_block* curr_block = cache[i];
    if (curr_block->is_valid) {
      if (curr_block->is_dirty) {
        block_write(fs_device, curr_block->sector, curr_block->data);
      }
      free(curr_block->data);
    }
    free(curr_block);
  }

  lock_release(&cache_lock);
}

void reset_cache() {
  close_cache();

  // recreate the buffer cache
  clock_arm = 0;
  cache_size = 0;
  cache_hit_count = 0;
  cache_miss_count = 0;

  for (int i = 0; i < 64; i++) {
    cache[i] = malloc(sizeof(struct cache_block));
    if (cache[i] == NULL)
      return;

    lock_init(&cache[i]->block_lock); // not sure if i re-init this
    cache[i]->is_dirty = false;
    cache[i]->is_accessed = false;
    cache[i]->is_valid = false;
  }
}

int evict_block() {
  lock_acquire(&cache_lock);

  struct cache_block* rm_block = NULL;
  while (rm_block == NULL) {
    struct cache_block* curr_block = cache[clock_arm];

    if (curr_block->is_accessed) {
      rm_block = curr_block;
    } else
      curr_block->is_accessed = true;

    clock_arm = (clock_arm + 1) % 64;
  }

  lock_release(&cache_lock);

  lock_acquire(&rm_block->block_lock);
  if (rm_block->is_dirty) {
    block_write(fs_device, rm_block->sector, rm_block->data);
  }

  rm_block->is_valid = false;
  free(rm_block->data);
  lock_release(&rm_block->block_lock);

  return (clock_arm - 1) % 64;
}

struct cache_block* fetch_block(block_sector_t sector) {
  struct cache_block* block = NULL;
  bool found = 0;

  lock_acquire(&cache_lock);
  for (int i = 0; i < cache_size; i++) {
    struct cache_block* curr = cache[i];
    if (curr->is_valid && curr->sector == sector) {
      block = curr;
      found = 1;
      break;
    }
  }
  lock_release(&cache_lock);

  if (found) {
    cache_hit_count++;
  } else {
    cache_miss_count++;
  }

  if (block == NULL) {
    uint8_t* block_data = malloc(BLOCK_SECTOR_SIZE);
    if (block_data == NULL)
      return NULL;

    if (cache_size == 64) {
      int pos = evict_block();
      block = cache[pos];
    } else {
      block = cache[cache_size];
      cache_size++;
    }

    lock_acquire(&block->block_lock);
    block->is_valid = true;
    block->sector = sector;
    block->is_dirty = false;
    block->is_accessed = false;
    block->data = block_data;
    block_read(fs_device, sector, block->data);
    lock_release(&block->block_lock);
  }

  return block;
}

void smart_block_write(block_sector_t sector, void* buffer) {
  smart_write(sector, buffer, 0, BLOCK_SECTOR_SIZE);
}

void smart_block_read(block_sector_t sector, void* buffer) {
  smart_read(sector, buffer, 0, BLOCK_SECTOR_SIZE);
}

void smart_write(block_sector_t sector, void* buffer, size_t offset, size_t bytes_written) {
  struct cache_block* block = fetch_block(sector);
  if (block == NULL)
    return;

  lock_acquire(&block->block_lock);
  memcpy(block->data + offset, buffer, bytes_written);
  block->is_dirty = true;
  block->is_accessed = false;
  lock_release(&block->block_lock);
}

void smart_read(block_sector_t sector, void* buffer, size_t offset, size_t bytes_read) {
  struct cache_block* block = fetch_block(sector);
  if (block == NULL)
    return;

  lock_acquire(&block->block_lock);
  memcpy(buffer, block->data + offset, bytes_read);
  block->is_accessed = false;
  lock_release(&block->block_lock);
}

size_t get_cache_hits() { return cache_hit_count; }

size_t get_cache_misses() { return cache_miss_count; }