#include <debug.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
//p4的第一问要求我们实现buffer cache 这里我们定义cache区域的大小为64字节
#define CACHE_SIZE 64
//三个bool变量用来分辨 是否可以用来装入 是否脏页 是否 有权现
struct cache_tab {
  bool isoccupied;  
  bool isdirty;    
  bool access;    
  block_sector_t disk_s;//磁盘块
  uint8_t buffer[BLOCK_SECTOR_SIZE];
};


static struct cache_tab cache[CACHE_SIZE];
static struct lock cache_lock;
/*******定义文件内函数 方便进行计算********/
//刷新cache
static struct cache_tab* cache_get (block_sector_t sector);
static struct cache_tab* cache_release(void);
static void cache_flush (struct cache_tab *entry);
//implemtention
void cache_init (void){
  lock_init (&cache_lock);
  size_t i;
  for (i = 0; i < CACHE_SIZE; ++ i)
  {
    cache[i].isoccupied = false;
  }
}




void cache_close (void){
  lock_acquire (&cache_lock);

  size_t i;
  for (i = 0; i < CACHE_SIZE; ++ i)
  {
    if (cache[i].isoccupied == false) continue;
    cache_flush( &(cache[i]) );
  }

  lock_release (&cache_lock);
}


void cache_read (block_sector_t sector, void *target){
  lock_acquire (&cache_lock);

  struct cache_tab *s = cache_get (sector);
  if (s == NULL) {
    s = cache_release();
    ASSERT (s != NULL && s->isoccupied == false);
    s->isoccupied = true;
    s->disk_s = sector;
    s->isdirty = false;
    block_read (fs_device, sector, s->buffer);
  }

  s->access = true;
  memcpy (target, s->buffer, BLOCK_SECTOR_SIZE);

  lock_release (&cache_lock);
}

void cache_write (block_sector_t sector, const void *src){
	lock_acquire (&cache_lock);

  	struct cache_tab *slot = cache_get (sector);
  	if (slot == NULL) {
	    slot = cache_release();
		//确保弹出的块不是空块且不可读
	    ASSERT (slot != NULL && slot->isoccupied == false);
	    slot->isoccupied = true;
	    slot->disk_s = sector;
		//其实这里不该用脏块的定义表示数据已经被填充 但是为了数据结构的精简化
	    slot->isdirty = false;
	    block_read (fs_device, sector, slot->buffer);
  	}

  	slot->access = true;
  	slot->isdirty = true;
  	memcpy (slot->buffer, src, BLOCK_SECTOR_SIZE);

  	lock_release (&cache_lock);
}

static void cache_flush (struct cache_tab *entry){
  ASSERT (lock_held_by_current_thread(&cache_lock));
  ASSERT (entry != NULL && entry->isoccupied == true);

  if (entry->isdirty) {
    block_write (fs_device, entry->disk_s, entry->buffer);
    entry->isdirty = false;
  }
}
static struct cache_tab* cache_get (block_sector_t sec){
  size_t i;
  for (i = 0; i < CACHE_SIZE; ++ i)
  {
    if (cache[i].isoccupied == false) continue;
    if (cache[i].disk_s == sec) {
      return &(cache[i]);
    }
  }
  return NULL; 
}

//release依靠时钟算法

static struct cache_tab* cache_release(void){
  ASSERT (lock_held_by_current_thread(&cache_lock));

  // clock algorithm
  static size_t C = 0;
  while (true) {
    if (cache[C].isoccupied == false) {
      return &(cache[C]);
    }
    if (cache[C].access) {
      cache[C].access = false;
    }
    else break;
    C++;
    C%= CACHE_SIZE;
  }
  struct cache_tab *slot = &cache[C];
  if (slot->isdirty) {
    cache_flush (slot);
  }
  slot->isoccupied = false;
  return slot;
}


