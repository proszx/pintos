#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"
#ifndef VM

#define frame_allocate(x, y) palloc_get_page(x)
#define frame_free(x) palloc_free_page(x)
#endif
#ifdef DEBUG
#define _DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
#define _DEBUG_PRINTF(...) /* do nothing */
#endif


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void push_arguments (const char *[], int cnt, void **esp);

/* Starts a new thread running a user program loaded from
   `cmdline`. The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
pid_t
process_execute (const char *cmdline)
{
  char *cmd_cp = NULL, *file_name = NULL;
  char *save_ptr = NULL;
  struct process_control_block *pcb = NULL;
  tid_t tid;

  //进程拷贝
  cmd_cp = palloc_get_page (0);
  if (cmd_cp == NULL) {
    goto execute_failed;
  }
  strlcpy (cmd_cp, cmdline, PGSIZE);

  // 从进程参数中解析文件名，应该进行一份拷贝再进行测试
  file_name = palloc_get_page (0);
  if (file_name == NULL) {
    goto execute_failed;
  }
  strlcpy (file_name, cmdline, PGSIZE);
  file_name = strtok_r(file_name, " ", &save_ptr);

  //开启一个新的线程解析文件名

  // 
  pcb = palloc_get_page(0);
  if (pcb == NULL) {
    goto execute_failed;
  }

  // 这时进程id还没有获取，在开始进程这个函数中才会被赋予
  // 这阶段主要进行一些准备工作
  // 将进程id加载进chlist
  pcb->pid = PID_INITIALIZING;
  pcb->parent_thread = thread_current();

  pcb->cmdline = cmd_cp;
  pcb->waiting = false;
  pcb->exited = false;
  pcb->orphan = false;
  pcb->exitcode = -1; 

  sema_init(&pcb->sema_initialization, 0);
  sema_init(&pcb->sema_wait, 0);

  // 创建线程
  tid = thread_create (file_name, PRI_DEFAULT, start_process, pcb);

  if (tid == TID_ERROR) {
    goto execute_failed;//使用goto语句进行跳转，一般不指望这么做但是为了程序不超时
  }

  // 等待初始化完成锁住 semaphone
  sema_down(&pcb->sema_initialization);
  if(cmd_cp) {
    palloc_free_page (cmd_cp);
  }

  // 进程创建完成，现在加载子进程列表
  if(pcb->pid >= 0) {
    list_push_back (&(thread_current()->ch_list), &(pcb->elem));
  }

  palloc_free_page (file_name);
  return pcb->pid;

execute_failed:
  // release allocated memory and return
  if(cmd_cp) palloc_free_page (cmd_cp);
  if(file_name) palloc_free_page (file_name);
  if(pcb) palloc_free_page (pcb);

  return PID_ERROR;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *pcb_)
{
  struct thread *t = thread_current();
  struct process_control_block *pcb = pcb_;

  char *file_name = (char*) pcb->cmdline;
  bool success = false;

  // cmdline handling
  const char **cmdline_tokens = (const char**) palloc_get_page(0);

  if (cmdline_tokens == NULL) {
    printf("[Error] Kernel Error: Not enough memory\n");
    goto finish_step; // pid being -1, release lock, clean resources
  }

  char* token;
  char* save_ptr;
  int cnt = 0;
  for (token = strtok_r(file_name, " ", &save_ptr); token != NULL;
      token = strtok_r(NULL, " ", &save_ptr))
  {
    cmdline_tokens[cnt++] = token;
  }

  /* Initialize interrupt frame and load executable. */
  struct intr_frame if_;
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
  if (success) {
    push_arguments (cmdline_tokens, cnt, &if_.esp);
  }
  palloc_free_page (cmdline_tokens);

  
  if (pcb->parent_thread != NULL && pcb->parent_thread->cwd != NULL) {
    
    t->cwd = dir_reopen(pcb->parent_thread->cwd);
  }
  else {
    t->cwd = dir_open_root();
  }

finish_step:

  //分配pcb进程控制块
  //让tid=pid完成映射
  // process_execute()完成子列表加载
  pcb->pid = success ? (pid_t)(t->tid) : PID_ERROR;
  t->pcb = pcb;

  // 唤醒semaphone在进程执行过程中
  sema_up(&pcb->sema_initialization);

  //加载错误就退出
  if (!success)
    _exit (-1);

  /*通过模拟来自的返回来启动用户进程中断，由intr_exit实现（在thread/ INTR-stubs.S）。 因为intr_exit占用了它的全部以“struct intr_frame”的形式在堆栈上的参数，将堆栈指针（％esp）指向用户堆栈帧然后跳到它。 */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct thread *t = thread_current ();
  struct list *child_list = &(t->ch_list);

  // 让线程子列表的tid付给child_tid
  struct process_control_block *child_pcb = NULL;
  struct list_elem *it = NULL;

  if (!list_empty(child_list)) {
    for (it = list_front(child_list); it != list_end(child_list); it = list_next(it)) {
      struct process_control_block *pcb = list_entry(
          it, struct process_control_block, elem);

      if(pcb->pid == child_tid) { // 从pcb中加载子进程
        child_pcb = pcb;
        break;
      }
    }
  }

  //子进程未找到返回-1
  if (child_pcb == NULL) {
    _DEBUG_PRINTF("[DEBUG] wait(): child not found, pid = %d\n", child_tid);
    return -1;
  }

  if (child_pcb->waiting) {
    _DEBUG_PRINTF("[DEBUG] wait(): child found, pid = %d, but it is already waiting\n", child_tid);
    return -1; // a process may wait for any fixed child at most once
  }
  else {
    child_pcb->waiting = true;
  }

  // 等到子进程完毕process_exit（）以发信号通知semaphore
  if (! child_pcb->exited) {
    sema_down(& (child_pcb->sema_wait));
  }
  ASSERT (child_pcb->exited == true);

  //从子进程列表移除
  ASSERT (it != NULL);
  list_remove (it);

  //返回子进程退出码
  int retcode = child_pcb->exitcode;

  //释放子进程的pcb对象。
   //保证子进程已退出
  palloc_free_page(child_pcb);

  return retcode;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* 首先清理资源*/
  // 1.文件描述服
  struct list *fdlist = &cur->file_des;
  while (!list_empty(fdlist)) {
    struct list_elem *e = list_pop_front (fdlist);
    struct file_desc *desc = list_entry(e, struct file_desc, elem);
    file_close(desc->file);
    palloc_free_page(desc); // see sys_open()
  }
#ifdef VM
	struct list *mmlist=&cur->file_des;
	while(!list_empty(mmlist)){
		struct list_elem *e=list_begin(mmlist);
		struct mmap_desc *desc=list_entry(e,struct mmap_desc,elem);
		ASSERT(_munmap(desc->id)==true);
	}
#endif
  
  if(cur->cwd) dir_close (cur->cwd);

  //清理所有子进程的pcb
  struct list *child_list = &cur->ch_list;
  while (!list_empty(child_list)) {
    struct list_elem *e = list_pop_front (child_list);
    struct process_control_block *pcb;
    pcb = list_entry(e, struct process_control_block, elem);
    if (pcb->exited == true) {
      // 当所有的子进程pcb完全退出 释放pcb所占内存
      palloc_free_page (pcb);
    } else {
      //否则 这时候子进程成为孤单进程 换句话说它是个孤儿了 没有pcb保护了
      // 等父进程先完成退出
      pcb->orphan = true;
      pcb->parent_thread = NULL;
    }
  }

  //2释放文件
  if(cur->self) {
    file_allow_write(cur->self);
    file_close(cur->self);
  }

 //从wait（）中取消阻止等待的父进程（如果有）。现在它的资源（页面上的pcb等）可以被释放。
 //将pcb->设置为true的顺序很重要这 为了保证在释放进程和pcb时不再使用它（即在wait（）程序中
  cur->pcb->exited = true;
  bool cur_orphan = cur->pcb->orphan;
  sema_up (&cur->pcb->sema_wait);

  // 如果是孤儿进程 ，pcb应该被free掉，让他自己销毁掉自己
  if (cur_orphan) {
    palloc_free_page (& cur->pcb);
  }

#ifdef VM
	pgtab_destroy(cur->page_table);
	cur->page_table=NULL;
#endif

  //销毁当前线程的页目录，并且让页回到和心态
  pd = cur->pdir;
  if (pd != NULL)
    {
    //在切换页面目录之前cur-> pagedir为NULL，这样定时器中断就无法切换回进程页面目录。 
    //我们必须激活基页目录在销毁进程页面之前目录，或我们的活动页面目录将是一个已被释放（并清除）。
      cur->pdir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* 激活线程页表 */
  pagedir_activate (t->pdir);

  /* 进程中断在内核栈 */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  //激活创建所有线程页表
  t->pdir = pagedir_create ();
#ifdef VM
  t->page_table=pgtab_create();
#endif
  if (t->pdir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  //读取文件头
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
         break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  // 从磁盘读取初始部分并将其余部分归零。
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  /* Deny writes to executables. */
  file_deny_write (file);
  thread_current()->self = file;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */

  // do not close file here, postpone until it terminates
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
#ifdef VM
		struct thread *current=thread_current();
		ASSERT(pagedir_get_page(current->pdir,upage)==NULL);
		if(!pgtab_loadfilesys(current->page_table, upage,file,ofs, page_read_bytes,page_zero_bytes,writable)){ 
			return false;
		}
#else

      /* Get a page of memory. */
       uint8_t *kpage =frame_allocate (PAL_USER | PAL_ZERO, PHYS_BASE - PGSIZE);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          frame_free(kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          frame_free(kpage);
          return false;
        }
#endif
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
#ifdef VM
		ofs+=PGSIZE;
#endif
    }
  return true;
}


/*
 * Push arguments into the stack region of user program
 * (specified by esp), according to the calling convention.
 */
static void
push_arguments (const char* cmdline_tokens[], int argc, void **esp)
{
  ASSERT(argc >= 0);

  int i, len = 0;
  void* argv_addr[argc];
  for (i = 0; i < argc; i++) {
    len = strlen(cmdline_tokens[i]) + 1;
    *esp -= len;
    memcpy(*esp, cmdline_tokens[i], len);
    argv_addr[i] = *esp;
  }

  // word align
  *esp = (void*)((unsigned int)(*esp) & 0xfffffffc);

  // last null
  *esp -= 4;
  *((uint32_t*) *esp) = 0;

  // setting **esp with argvs
  for (i = argc - 1; i >= 0; i--) {
    *esp -= 4;
    *((void**) *esp) = argv_addr[i];
  }

  // setting **argv (addr of stack, esp)
  *esp -= 4;
  *((void**) *esp) = (*esp + 4);

  // setting argc
  *esp -= 4;
  *((int*) *esp) = argc;

  // setting ret addr
  *esp -= 4;
  *((int*) *esp) = 0;

}


/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  // upage address is the first segment of stack.
  kpage =frame_allocate(PAL_USER | PAL_ZERO,PHYS_BASE-PGSIZE);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        frame_free(kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  bool success = (pagedir_get_page (t->pdir, upage) == NULL);
  success = success && pagedir_set_page (t->pdir, upage, kpage, writable);
#ifdef VM
	success=success&&pgtab_loadframe(t->page_table,upage,kpage);
	if(success) frame_unhook(kpage);
#endif
  return success;
}




