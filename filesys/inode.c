#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"


#define INODE_MAGIC 0x494e4f44

#define BLOCK_SIZE 123
#define BLOCKS_PERSEC 128


struct inode_disk
  {

    block_sector_t direct_blocks[BLOCK_SIZE];
    block_sector_t ind_block;
    block_sector_t dind_block;
    bool is_dir;
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
  };

struct inode_indsector {
  block_sector_t blocks[BLOCKS_PERSEC];
};

static bool inode_allocate (struct inode_disk *disk_inode);
static bool inode_reserve (struct inode_disk *disk_inode, off_t length);
static bool inode_deallocate (struct inode *inode);
static bool inode_indreserve (block_sector_t* p_entry, size_t num_sectors, int level);
static void inode_deindall (block_sector_t entry, size_t num_sectors, int level);

static inline size_t bytes_to_sectors (off_t size){
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

static inline size_t
cmp (size_t a, size_t b)
{
  return a < b ? a : b;
}

/* In-memory inode. */
struct inode
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };
static block_sector_t index_to_sector (const struct inode_disk *idisk, off_t index);
static bool inode_indreserve (block_sector_t* p_entry, size_t num_sectors, int level);
static bool inode_deallocate (struct inode *inode);
static void inode_deindall (block_sector_t entry, size_t num_sectors, int level);

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  if (0 <= pos && pos < inode->data.length) {
    // sector index
    off_t index = pos / BLOCK_SECTOR_SIZE;
    return index_to_sector (&inode->data, index);
  }
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void)
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_dir = is_dir;
      if (inode_allocate (disk_inode))
        {
          cache_write (sector, disk_inode);
          success = true;
        }
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  	//检查inode是否打开
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          return inode;
        }
    }

	//初始化
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  cache_read (inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      if (inode->removed)
        {
          free_map_release (inode->sector, 1);
 /*进行改动优化 适用cache*/     inode_deallocate (inode);
        }

      free (inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_read (sector_idx, buffer + bytes_read);
        }
      else
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cache_read (sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode).
   */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  //超出EOF：扩展文件
  if( byte_to_sector(inode, offset + size - 1) == -1u ) {
    bool success;
    success = inode_reserve (& inode->data, offset + size);
    if (!success) return 0;    
    inode->data.length = offset + size;
    cache_write (inode->sector, & inode->data);
  }

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          cache_write (sector_idx, buffer + bytes_written);
        }
      else
        {
          /* We need a bounce buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            cache_read (sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cache_write (sector_idx, bounce);/*进行改动优化 适用cache*/
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

/* Returns whether the file is directory or not. */
bool
inode_isdir (const struct inode *inode)
{
  return inode->data.is_dir;
}

/* Returns whether the file is removed or not. */
bool
inode_isremove(const struct inode *inode)
{
  return inode->removed;
}

static
bool inode_allocate (struct inode_disk *disk_inode)
{
  return inode_reserve (disk_inode, disk_inode->length);
}

/********************************************/



static block_sector_t index_to_sector (const struct inode_disk *idisk, off_t index){
  off_t index_base = 0, index_limit = 0;   // 定义基索引和限制索引
  block_sector_t ret;

  // 直接寻址
  index_limit += BLOCK_SIZE * 1;
  if (index < index_limit) {
    return idisk->direct_blocks[index];
  }
  index_base = index_limit;

  // 简单间接寻址
  index_limit += 1 * BLOCKS_PERSEC;
  if (index < index_limit) {
    struct inode_indsector *indirect_idisk;
    indirect_idisk = calloc(1, sizeof(struct inode_indsector));
    cache_read (idisk->ind_block, indirect_idisk);

    ret = indirect_idisk->blocks[ index - index_base ];
    free(indirect_idisk);

    return ret;
  }
  index_base = index_limit;

  // 双向简单间接寻址
  index_limit += 1 * BLOCKS_PERSEC * BLOCKS_PERSEC;
  if (index < index_limit) {
    // 分两极文件块索引
    off_t index_first =  (index - index_base) / BLOCKS_PERSEC;
    off_t index_second = (index - index_base) % BLOCKS_PERSEC;
    struct inode_indsector *indirect_idisk;
    indirect_idisk = calloc(1, sizeof(struct inode_indsector));

    cache_read (idisk->dind_block, indirect_idisk);
    cache_read (indirect_idisk->blocks[index_first], indirect_idisk);
    ret = indirect_idisk->blocks[index_second];

    free(indirect_idisk);
    return ret;
  }

  // error
  return -1;
}
static bool inode_indreserve (block_sector_t* p_entry, size_t num_sectors, int level){
  static char zeros[BLOCK_SECTOR_SIZE];
  ASSERT (level <= 2);

  if (level == 0) {
  
    if (*p_entry == 0) {
      if(! free_map_allocate (1, p_entry))
        return false;
      cache_write (*p_entry, zeros);
    }
    return true;
  }

  struct inode_indsector ind_block;
  if(*p_entry == 0) {
    free_map_allocate (1, p_entry);
    cache_write (*p_entry, zeros);
  }
  cache_read(*p_entry, &ind_block);

  size_t unit = (level == 1 ? 1 : BLOCKS_PERSEC);
  size_t i, l = DIV_ROUND_UP (num_sectors, unit);

  for (i = 0; i < l; ++ i) {
    size_t subsize = cmp(num_sectors, unit);
    if(! inode_indreserve (& ind_block.blocks[i], subsize, level - 1))
      return false;
    num_sectors -= subsize;
  }

  ASSERT (num_sectors == 0);
  cache_write (*p_entry, &ind_block);
  return true;
}

static bool inode_reserve (struct inode_disk *disk_inode, off_t length){
  static char zeros[BLOCK_SECTOR_SIZE];
  if (length < 0) return false;

  size_t num_sectors = bytes_to_sectors(length);
  size_t i, l;

  // 直接寻址
  l = cmp(num_sectors, BLOCK_SIZE * 1);
  for (i = 0; i < l; ++ i) {
    if (disk_inode->direct_blocks[i] == 0) { 
      if(! free_map_allocate (1, &disk_inode->direct_blocks[i]))
        return false;
      cache_write (disk_inode->direct_blocks[i], zeros);
    }
  }
  num_sectors -= l;
  if(num_sectors == 0) return true;

  // 
  l = cmp(num_sectors, 1 * BLOCKS_PERSEC);
  if(! inode_indreserve (& disk_inode->ind_block, l, 1))
    return false;
  num_sectors -= l;
  if(num_sectors == 0) return true;

  // 双向简单间接寻址
  l = cmp(num_sectors, 1 * BLOCKS_PERSEC * BLOCKS_PERSEC);
  if(! inode_indreserve (& disk_inode->dind_block, l, 2))
    return false;
  num_sectors -= l;
  if(num_sectors == 0) return true;

  ASSERT (num_sectors == 0);
  return false;
}

static bool inode_deallocate (struct inode *inode){
  off_t file_length = inode->data.length; // bytes
  if(file_length < 0) return false;

  // (remaining) number of sectors, occupied by this file.
  size_t num_sectors = bytes_to_sectors(file_length);
  size_t i, l;

  // 直接寻址
  l = cmp(num_sectors, BLOCK_SIZE * 1);
  for (i = 0; i < l; ++ i) {
    free_map_release (inode->data.direct_blocks[i], 1);
  }
  num_sectors -= l;

  // (简单间接寻址
  l = cmp(num_sectors, 1 * BLOCKS_PERSEC);
  if(l > 0) {
    inode_deindall (inode->data.ind_block, l, 1);
    num_sectors -= l;
  }

  // 双向简单间接寻址
  l = cmp(num_sectors, 1 * BLOCKS_PERSEC * BLOCKS_PERSEC);
  if(l > 0) {
    inode_deindall (inode->data.dind_block, l, 2);
    num_sectors -= l;
  }

  ASSERT (num_sectors == 0);
  return true;
}

static void inode_deindall (block_sector_t entry, size_t num_sectors, int level){
  ASSERT (level <= 2);

  if (level == 0) {
    free_map_release (entry, 1);
    return;
  }

  struct inode_indsector ind_block;
  cache_read(entry, &ind_block);

  size_t unit = (level == 1 ? 1 : BLOCKS_PERSEC);
  size_t i, l = DIV_ROUND_UP (num_sectors, unit);

  for (i = 0; i < l; ++ i) {
    size_t subsize = cmp(num_sectors, unit);
    inode_deindall (ind_block.blocks[i], subsize, level - 1);
    num_sectors -= subsize;
  }

  ASSERT (num_sectors == 0);
  free_map_release (entry, 1);
}

