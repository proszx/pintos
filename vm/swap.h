#ifndef VM_SWAP_H
#define VM_SWAP_H

typedef uint32_t index_swap;//交换索引


/*
交换区初始化
进入交换区
出交换区
释放交换区
*/
void vm_swap_init (void);
index_swap vm_swap_out (void *page);
void vm_swap_in (index_swap swap_index, void *page);
void vm_swap_free (index_swap swap_index);


#endif /* vm/swap.h */
