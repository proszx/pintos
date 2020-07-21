#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include "lib/kernel/hash.h"

#include "threads/synch.h"
#include "threads/palloc.h"


//frame初始化
void frame_init (void);

void* frame_allocate (enum palloc_flags flags, void *upage);
void frame_free (void*);
void frame_remove (void*);
void frame_hook (void* kpage);
void frame_unhook (void* kpage);

#endif /* vm/frame.h */
