#include <bitmap.h>
#include "threads/vaddr.h"
#include "devices/block.h"
#include "vm/swap.h"

static struct block *swap_block;
static struct bitmap *swap_available;
//					每页大小    总大小    时钟寄存器大小
static const size_t PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE;


static size_t size;

void
vm_swap_init (){
  ASSERT (PER_PAGE > 0); 

  // 初始化交换区block_get_role in block.h
  swap_block = block_get_role(BLOCK_SWAP);
  if(swap_block == NULL) {
    PANIC ("Error: Can't initialize swap block");
    NOT_REACHED ();//in debug.h
  }
  size = block_size(swap_block) / PER_PAGE;
  swap_available = bitmap_create(size);
  bitmap_set_all(swap_available, true);
}


index_swap vm_swap_out (void *page){
  //确保每页都在用户态虚拟地址
  ASSERT (page >= PHYS_BASE);

  //找到可用快
  size_t swap_index = bitmap_scan (swap_available, 0, 1, true);

  size_t i;
  for (i = 0; i < PER_PAGE; ++ i) {
	//				交换块 		寄存器数量 					目标地址
    block_write(swap_block,swap_index * PER_PAGE + i, page + (BLOCK_SECTOR_SIZE * i));
  }

  bitmap_set(swap_available, swap_index, false);
  return swap_index;
}


void vm_swap_in (index_swap swap_index, void *page){
  ASSERT (page >= PHYS_BASE);
  ASSERT (swap_index < size);
  if (bitmap_test(swap_available, swap_index) == true) {
    PANIC ("Error, invalid read access to unassigned swap block");
  }

  size_t i;
  for (i = 0; i < PER_PAGE; ++ i) {
    block_read (swap_block,swap_index * PER_PAGE + i,page + (BLOCK_SECTOR_SIZE * i));
  }

  bitmap_set(swap_available, swap_index, true);
}

void vm_swap_free (index_swap swap_index){
  //检查交换区
  ASSERT (swap_index < size);
  if (bitmap_test(swap_available, swap_index) == true) {
    PANIC ("Error, invalid free request to unassigned swap block");
  }
  bitmap_set(swap_available, swap_index, true);
}
