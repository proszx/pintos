#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "vm/swap.h"
#include <hash.h>
#include "filesys/off_t.h"

enum page_status {
  ALL_ZERO,         // 没有加载
  ON_FRAME,         // 内存活跃
  ON_SWAP,          // 交换
  FROM_FILESYS      // 与文件系统交互
};


struct page_table
  {
    //利用哈希表存储内存表
    struct hash page_map;
  };

struct page_tab_ent
  {
    void *upage;              //用户虚拟地址
    void *kpage;              //内核tai虚拟内存所占地址
    struct hash_elem elem;	  //哈希组件
    enum page_status status;  //状态枚举标志位
    bool dirty;               //脏页标志位
    index_swap index;  //交换索引

    //因为虚拟内存部分涉嫌到与文件系统进行交互这里调用文件符和文件结构体
    struct file *file;
    off_t offset;
    uint32_t read_bytes, zero_bytes;
    bool writable;
  };


// 内存页的建立
struct page_table* pgtab_create (void);
//内存页的销毁
void pgtab_destroy (struct page_table *);
//内存页加载frame
bool pgtab_loadframe (struct page_table *supt, void *upage, void *kpage);
//内存页加载空页
bool pgtab_loadzpage (struct page_table *supt, void *);
//内存切换
bool pgtab_setswap (struct page_table *supt, void *, index_swap);
//内存页加载文件系统
bool pgtab_loadfilesys (struct page_table *supt, void *page,
    struct file * file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
//查看进程并返回内存调用详表
struct page_tab_ent* pgtab_lookup (struct page_table *supt, void *);
//进入
bool pgtab_entry (struct page_table *, void *page);
//设置脏页标示
bool pglab_setdirty (struct page_table *supt, void *, bool);
//加载页面
bool pglab_loadpage(struct page_table *supt, uint32_t *pagedir, void *upage);
//取消锁定映射
bool pgtab_mm_unmap(struct page_table *supt, uint32_t *pagedir,
    void *page, struct file *f, off_t offset, size_t bytes);
//固定页面
void pgtab_hook(struct page_table *supt, void *page);
//解锁页面
void pgtab_unhook(struct page_table *supt, void *page);

#endif
