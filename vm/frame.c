#include <hash.h>
#include <list.h>
#include <stdio.h>
#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"

#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"


//所
static struct lock frame_lock;
//集合
static struct hash frame_map;

//
static struct list frame_list;      //frame队列
static struct list_elem *clock_ptr; //时钟队列指针

static unsigned hash_f(const struct hash_elem *elem, void *aux);
static bool     cmp_f(const struct hash_elem *, const struct hash_elem *, void *aux);//使得队列按照内核页大小降序排列
struct frame_table* clock_next(void);
/**
 * Frame Table Entry
 */
struct frame_table
  {
    void *kpage;               //内核页

    struct hash_elem helem;    //哈希组建
    struct list_elem lelem;    //队列组件

    void *upage;               //用户页
    struct thread *t;          //当前线程
    bool islock;               //锁
  };


static struct frame_table* pick_frameout(uint32_t* pagedir);
static void vm_frame_do_free (void *kpage, bool free_page);


void
frame_init ()
{
  lock_init (&frame_lock);
  hash_init (&frame_map, hash_f, cmp_f, NULL);
  list_init (&frame_list);
  clock_ptr = NULL;
}

// 生成新的frame
void* frame_allocate (enum palloc_flags flags, void *upage){
  lock_acquire (&frame_lock);

  void *frame_page = palloc_get_page (PAL_USER | flags);
  if (frame_page == NULL) {
    //页为空换出页
    struct frame_table *f_tab = pick_frameout( thread_current()->pdir );
#if DEBUG
    printf("f_tab: %x th=%x, pagedir = %x, up = %x, kp = %x, hash_size=%d\n", f_tab, f_tab->t,
        f_tab->t->pdir, f_tab->upage, f_tab->kpage, hash_size(&frame_map));
#endif
    ASSERT (f_tab != NULL && f_tab->t != NULL);
    //用交换区清理替代映射
    ASSERT (f_tab->t->pdir != (void*)0xcccccccc);
    pagedir_clear_page(f_tab->t->pdir, f_tab->upage);
    bool is_dirty = false;
    is_dirty = is_dirty || pagedir_is_dirty(f_tab->t->pdir, f_tab->upage);
    is_dirty = is_dirty || pagedir_is_dirty(f_tab->t->pdir, f_tab->kpage);

    index_swap swap_idx = vm_swap_out( f_tab->kpage );
    pgtab_setswap(f_tab->t->page_table, f_tab->upage, swap_idx);
    pglab_setdirty(f_tab->t->page_table, f_tab->upage, is_dirty);
    vm_frame_do_free(f_tab->kpage, true); 

    frame_page = palloc_get_page (PAL_USER | flags);
    ASSERT (frame_page != NULL); 
  }

  struct frame_table *frame = malloc(sizeof(struct frame_table));
  if(frame == NULL) {
    lock_release (&frame_lock);
    return NULL;
  }

  frame->t = thread_current ();
  frame->upage = upage;
  frame->kpage = frame_page;
  frame->islock = true;         

  // 塞入表
  hash_insert (&frame_map, &frame->helem);
  list_push_back (&frame_list, &frame->lelem);

  lock_release (&frame_lock);
  return frame_page;
}

//释放框架
void frame_free (void *kpage){
  lock_acquire (&frame_lock);
  vm_frame_do_free (kpage, true);
  lock_release (&frame_lock);
}

//仅仅移出表
void frame_remove (void *kpage){
  lock_acquire (&frame_lock);
  vm_frame_do_free (kpage, false);
  lock_release (&frame_lock);
}

void vm_frame_do_free (void *kpage, bool free_page){
  ASSERT (lock_held_by_current_thread(&frame_lock) == true);
  ASSERT (is_kernel_vaddr(kpage));
  ASSERT (pg_ofs (kpage) == 0); 
  struct frame_table f_tmp;
  f_tmp.kpage = kpage;

  struct hash_elem *h = hash_find (&frame_map, &(f_tmp.helem));
  if (h == NULL) {
    PANIC ("The page to be freed is not stored in the table");
  }

  struct frame_table *f;
  f = hash_entry(h, struct frame_table, helem);

  hash_delete (&frame_map, &f->helem);
  list_remove (&f->lelem);

  // 释放资源
  if(free_page) palloc_free_page(kpage);
  free(f);
}

//列表中移除
struct frame_table* pick_frameout( uint32_t *pagedir )
{
  size_t n = hash_size(&frame_map);
  if(n == 0) PANIC("Frame table is empty, can't happen - there is a leak somewhere");

  size_t it;
  for(it = 0; it <= n + n; ++ it) 
  {
    struct frame_table *e = clock_next();
    if(e->islock) continue;
    else if( pagedir_is_accessed(pagedir, e->upage)) {
      pagedir_set_accessed(pagedir, e->upage, false);
      continue;
    }
    return e;
  }

  PANIC ("Can't evict any frame -- Not enough memory!\n");
}


struct frame_table* clock_next(void){
  if (list_empty(&frame_list))
    PANIC("Frame table is empty, can't happen - there is a leak somewhere");

  if (clock_ptr == NULL || clock_ptr == list_end(&frame_list))
    clock_ptr = list_begin (&frame_list);
  else
    clock_ptr = list_next (clock_ptr);

  struct frame_table *e = list_entry(clock_ptr, struct frame_table, lelem);
  return e;
}


static void vm_frame_set_islock (void *kpage, bool new_value){
  lock_acquire (&frame_lock);
  struct frame_table f_tmp;
  f_tmp.kpage = kpage;
  struct hash_elem *h = hash_find (&frame_map, &(f_tmp.helem));
  if (h == NULL) {
    PANIC ("The frame to be islock/unislock does not exist");
  }

  struct frame_table *f;
  f = hash_entry(h, struct frame_table, helem);
  f->islock = new_value;

  lock_release (&frame_lock);
}

void frame_unhook (void* kpage) {
  vm_frame_set_islock (kpage, false);
}

void frame_hook (void* kpage) {
  vm_frame_set_islock (kpage, true);
}



static unsigned hash_f(const struct hash_elem *elem, void *aux UNUSED){
  struct frame_table *entry = hash_entry(elem, struct frame_table, helem);
  return hash_bytes( &entry->kpage, sizeof entry->kpage );
}
static bool cmp_f(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
  struct frame_table *a_entry = hash_entry(a, struct frame_table, helem);
  struct frame_table *b_entry = hash_entry(b, struct frame_table, helem);
  return a_entry->kpage < b_entry->kpage;
}
