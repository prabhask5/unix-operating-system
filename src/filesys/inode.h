#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include <list.h>
struct bitmap;

void inode_init(void);
bool inode_create(block_sector_t, off_t, bool);
struct inode* inode_open(block_sector_t);
struct inode* inode_reopen(struct inode*);
block_sector_t inode_get_inumber(const struct inode*);
void inode_close(struct inode*);
void inode_remove(struct inode*);
off_t inode_read_at(struct inode*, void*, off_t size, off_t offset);
off_t inode_write_at(struct inode*, const void*, off_t size, off_t offset);
void inode_deny_write(struct inode*);
void inode_allow_write(struct inode*);
off_t inode_length(const struct inode*);

// added for proj 4 below
bool inode_is_dir(const struct inode* inode);
void close_cache(void);
void reset_cache(void);
int evict_block(void);
struct cache_block* fetch_block(block_sector_t);
void smart_block_write(block_sector_t, void*);
void smart_block_read(block_sector_t, void*);
void smart_write(block_sector_t, void*, size_t, size_t);
void smart_read(block_sector_t, void*, size_t, size_t);
size_t get_cache_hits(void);
size_t get_cache_misses(void);

#endif /* filesys/inode.h */
