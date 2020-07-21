#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#ifdef VM
#include "vm/page.h"
#endif
#ifdef DEBUG
#define _DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
#define _DEBUG_PRINTF(...) /* do nothing */
#endif

static void syscall_handler (struct intr_frame *);
static void mem_check(const uint8_t *a);
static int32_t mem_get(const uint8_t *u);
static bool mem_put(uint8_t *st,uint8_t bt);
static int memread_user(void *s,void *des,size_t byte);

enum fd_search_filter { FD_FILE = 1, FD_DIRECTORY = 2 };
static struct file_desc* find_file_desc(struct thread *, int fd, enum fd_search_filter flag);

void _halt (void);
void _exit (int);
pid_t _exec (const char *cmdline);
int _wait (pid_t pid);
bool create(const char* filename, unsigned initial_size);
bool remove(const char* filename);
int open(const char* file);
void seek(int fd, unsigned position);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
unsigned tell(int fd);
void close(int fd);
#ifdef VM
mmapid_t _mmap(int fd,void *);
bool _munmap(mmapid_t);
static struct mmap_desc *find_mmap_desc(struct thread*,mmapid_t fd);
void load_hook_page(const void *,size_t);
void load_unhook_page(const void *,size_t);
#endif
#ifdef FILESYS
bool _chdir(const char *f);//改变目录
bool _mkdir(const char *f);//创建目录
bool _readdir(int fd,char *f);//读目录
bool _isdir(int fd);//判断目录
int _inodenum(int fd);//判断inode数
#endif
struct lock filesys_lock;

void
syscall_init (void)
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// in case of invalid memory access, fail and exit.
static void invalid_access(void) {
  if (lock_held_by_current_thread(&filesys_lock))
    lock_release (&filesys_lock);

  _exit (-1);
  NOT_REACHED();
}           

static void
syscall_handler (struct intr_frame *f)
{
  int pt;
  ASSERT( sizeof(pt) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  memread_user(f->esp, &pt, sizeof(pt));
  _DEBUG_PRINTF ("[DEBUG] system call, number = %d!\n", pt);

  // Store the esp, which is needed in the page fault handler.
 
  thread_current()->cur_esp = f->esp;

  // Dispatch w.r.t system call number

  switch (pt) {
  case SYS_HALT: // 0 具体定义在lib/syscall-nr.h
    {
      _halt();
      NOT_REACHED();//在debug.h
      break;
    }

  case SYS_EXIT: // 1
    {
      int exitcode;
      memread_user(f->esp + 4, &exitcode, sizeof(exitcode));

      _exit(exitcode);
      NOT_REACHED();
      break;
    }

  case SYS_EXEC: // 2
    {
      void* cmdline;
      memread_user(f->esp + 4, &cmdline, sizeof(cmdline));

      int return_code = _exec((const char*) cmdline);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_WAIT: // 3
    {
      pid_t pid;
      memread_user(f->esp + 4, &pid, sizeof(pid_t));

      int ret = _wait(pid);
      f->eax = (uint32_t) ret;
      break;
    }

  case SYS_CREATE: // 4
    {
      const char* filename;
      unsigned initial_size;
      bool return_code;

      memread_user(f->esp + 4, &filename, sizeof(filename));
      memread_user(f->esp + 8, &initial_size, sizeof(initial_size));

      return_code = create(filename, initial_size);
      f->eax = return_code;
      break;
    }

  case SYS_REMOVE: // 5
    {
      const char* filename;
      bool return_code;

      memread_user(f->esp + 4, &filename, sizeof(filename));

      return_code = remove(filename);
      f->eax = return_code;
      break;
    }

  case SYS_OPEN: // 6
    {
      const char* filename;
      int return_code;

      memread_user(f->esp + 4, &filename, sizeof(filename));

      return_code = open(filename);
      f->eax = return_code;
      break;
    }

  case SYS_FILESIZE: // 7
    {
      int fd, return_code;
      memread_user(f->esp + 4, &fd, sizeof(fd));

      return_code = filesize(fd);
      f->eax = return_code;
      break;
    }

  case SYS_READ: // 8
    {
      int fd, return_code;
      void *buffer;
      unsigned size;

      memread_user(f->esp + 4, &fd, sizeof(fd));
      memread_user(f->esp + 8, &buffer, sizeof(buffer));
      memread_user(f->esp + 12, &size, sizeof(size));

      return_code = read(fd, buffer, size);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_WRITE: // 9
    {
      int fd, return_code;
      const void *buffer;
      unsigned size;

      memread_user(f->esp + 4, &fd, sizeof(fd));
      memread_user(f->esp + 8, &buffer, sizeof(buffer));
      memread_user(f->esp + 12, &size, sizeof(size));

      return_code = write(fd, buffer, size);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_SEEK: // 10
    {
      int fd;
      unsigned position;

      memread_user(f->esp + 4, &fd, sizeof(fd));
      memread_user(f->esp + 8, &position, sizeof(position));

      seek(fd, position);
      break;
    }

  case SYS_TELL: // 11
    {
      int fd;
      unsigned return_code;

      memread_user(f->esp + 4, &fd, sizeof(fd));

      return_code = tell(fd);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_CLOSE: // 12
    {
      int fd;
      memread_user(f->esp + 4, &fd, sizeof(fd));

      close(fd);
      break;
    }
#ifdef VM
	case SYS_MMAP:
	{
		int fd;
		void *a;
		
		memread_user(f->esp+4,&fd,sizeof(fd));
		memread_user(f->esp+8,&a,sizeof(a));
		mmapid_t r=_mmap(fd,a);
		f->eax=r;
		break;
	}
	case SYS_MUNMAP:
	{
		mmapid_t pid;
		memread_user(f->esp+4,&pid,sizeof(pid));
		_munmap(pid);
		break;
	}
#endif 
#ifdef FILESYS
	case SYS_CHDIR:{
		const char* file;
		int re;
		memread_user(f->esp+4,&file,sizeof(file));
		re=_chdir(file);
		f->eax=re;
    	break;
	}
    case SYS_MKDIR:{
		const char* file;
		int re;
		memread_user(f->esp+4,&file,sizeof(file));
		re=_mkdir(file);
		f->eax=re;
    	break;
	}
    case SYS_READDIR:{
		char* file;
		int fd;
		int re;
		memread_user(f->esp+4,&fd,sizeof(fd));
		memread_user(f->esp+8,&file,sizeof(file));
		re=_readdir(fd,file);
		f->eax=re;
    	break;
	}
    case SYS_ISDIR:{
		int fd;
		int re;
		memread_user(f->esp+4,&fd,sizeof(fd));
		re=_isdir(fd);
		f->eax=re;
    	break;
	}
   case SYS_INUMBER:{
		int fd;
		int re;
		memread_user(f->esp+4,&fd,sizeof(fd));
		re=_inodenum(fd);
		f->eax=re;
    	break;

	}
#endif
  /* unhandled case */
  default:
    printf("[ERROR] system call %d is unimplemented!\n", pt);

    // ensure that waiting (parent) process should wake up and terminate.
    _exit(-1);
    break;
  }

}

/****************** 系统调用的具体是现 ********************/

void _halt(void) {
  shutdown_power_off();
}

void _exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);

  //进程退出
   //使用信号量唤醒父进程
   //并传递返回码。
  struct process_control_block *pcb = thread_current()->pcb;
  if(pcb != NULL) {
    pcb->exitcode = status;
  }
  else {
    
  }

  thread_exit();
}

pid_t _exec(const char *cmdline) {
  _DEBUG_PRINTF ("[DEBUG] Exec : %s\n", cmdline);//系统定义输出

  // cmdline是用户内存上字符缓冲区的地址,检查是否正确
  mem_check((const uint8_t*) cmdline);

  lock_acquire (&filesys_lock); // 加载用户文件系统 ，最后测试有关文件系统 主要是文件锁的调用
  pid_t pid = process_execute(cmdline);
  lock_release (&filesys_lock);
  return pid;
}

int _wait(pid_t pid) {
  _DEBUG_PRINTF ("[DEBUG] Wait : %d\n", pid);
  return process_wait(pid);
}

bool create(const char* filename, unsigned initial_size) {
  bool return_code;

  mem_check((const uint8_t*) filename);

  lock_acquire (&filesys_lock);
  return_code = filesys_create(filename, initial_size, false);
  lock_release (&filesys_lock);
  return return_code;
}

bool remove(const char* filename) {
  bool return_code;
  //内存验证
  mem_check((const uint8_t*) filename);

  lock_acquire (&filesys_lock);
  return_code = filesys_remove(filename);
  lock_release (&filesys_lock);
  return return_code;
}

int open(const char* file) {
  
  mem_check((const uint8_t*) file);

  struct file* file_opened;
  struct file_desc* fd = palloc_get_page(0);
  if (!fd) {
    return -1;
  }

  lock_acquire (&filesys_lock);
  file_opened = filesys_open(file);
  if (!file_opened) {
    palloc_free_page (fd);
    lock_release (&filesys_lock);
    return -1;
  }

  fd->file = file_opened; //file save


  struct inode *inode = file_get_inode(fd->file);
  if(inode != NULL && inode_isdir(inode)) {
    fd->dir = dir_open( inode_reopen(inode) );
  }
  else fd->dir = NULL;

  struct list* fd_list = &thread_current()->file_des;
  if (list_empty(fd_list)) {

    fd->id = 3;
  }
  else {
    fd->id = (list_entry(list_back(fd_list), struct file_desc, elem)->id) + 1;
  }
  list_push_back(fd_list, &(fd->elem));
  lock_release (&filesys_lock);
  return fd->id;
}

int filesize(int fd) {
  struct file_desc* f;
  lock_acquire (&filesys_lock);
  f = find_file_desc(thread_current(), fd, FD_FILE);
  if(f == NULL) {
    lock_release (&filesys_lock);
    return -1;
  }
  int ret = file_length(f->file);
  lock_release (&filesys_lock);
  return ret;
}

void seek(int fd, unsigned position) {
  lock_acquire (&filesys_lock);
  struct file_desc* f = find_file_desc(thread_current(), fd, FD_FILE);

  if(f && f->file) {
    file_seek(f->file, position);
  }
  else
    return; // TODO need sys_exit?

  lock_release (&filesys_lock);
}

unsigned tell(int fd) {
  lock_acquire (&filesys_lock);
  struct file_desc* f= find_file_desc(thread_current(), fd, FD_FILE);

  unsigned ret;
  if(f && f->file) {
    ret = file_tell(f->file);
  }
  else
    ret = -1; // TODO need sys_exit?

  lock_release (&filesys_lock);
  return ret;
}

void close(int fd) {
  lock_acquire (&filesys_lock);
  struct file_desc* f = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);

  if(f && f->file) {
    file_close(f->file);
    if(f->dir) dir_close(f->dir);
    list_remove(&(f->elem));
    palloc_free_page(f);
  }
  lock_release (&filesys_lock);
}

int read(int fd, void *buffer, unsigned size) {
  
  mem_check((const uint8_t*) buffer);
  mem_check((const uint8_t*) buffer + size - 1);

  lock_acquire (&filesys_lock);
  int ret;

  if(fd == 0) { // stdin
    unsigned i;
    for(i = 0; i < size; ++i) {
      if(! mem_put(buffer + i, input_getc()) ) {
        lock_release (&filesys_lock);
        _exit(-1); // 寄存器错误
      }
    }
    ret = size;
  }
  else {
    // 文件读取
    struct file_desc* f = find_file_desc(thread_current(), fd, FD_FILE);
    if(f && f->file) {
#ifdef VM
	load_hook_page(buffer,size);
#endif
      ret = file_read(f->file, buffer, size);
#ifdef VM
	load_unhook_page(buffer,size);
#endif
 }
    else // 文件不存在
      ret = -1;
  }

  lock_release (&filesys_lock);
  return ret;
}

int write(int fd, const void *buffer, unsigned size) {
  //内存验证，同时参数必须有buffer指针和文件大小
  mem_check((const uint8_t*) buffer);
  mem_check((const uint8_t*) buffer+size-1);
  lock_acquire (&filesys_lock);
  int ret;

  if(fd == 1) { //写道输出
    putbuf(buffer, size);
    ret = size;
  }
  else {
    // 写道文件
    struct file_desc* f = find_file_desc(thread_current(), fd, FD_FILE);

    if(f && f->file) {
#ifdef VM
	load_hook_page(buffer,size);
#endif
      ret = file_write(f->file, buffer, size);
#ifdef VM
	load_unhook_page(buffer,size);
#endif

    }
    else 
      ret = -1;
  }

  lock_release (&filesys_lock);
  return ret;
}

static void
mem_check (const uint8_t *u) {
  // 检查内存和寄存器
  if(mem_get (u) == -1)
    invalid_access();
}
static int32_t
mem_get (const uint8_t *u) {
  if (! ((void*)u< PHYS_BASE)) {
    return -1;
  }

  int re;
  asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (re) : "m" (*u));
  return re;
}
static bool
mem_put (uint8_t *st, uint8_t byte) {
  
  if (! ((void*)st < PHYS_BASE)) {
    return false;
  }

  int error;

  
  asm ("movl $1f, %0; movb %b2, %1; 1:": "=&a" (error), "=m" (*st) : "q" (byte));
  return error!= -1;
}

static int
memread_user (void *src, void *dst, size_t bytes)
{
  int32_t value;
  size_t i;
  for(i=0; i<bytes; i++) {
    value = mem_get(src + i);
    if(value == -1) //寄存器或者内存地址错误
      invalid_access();

    *(char*)(dst + i) = value & 0xff;
  }
  return (int)bytes;
}
//降序找文件
static struct file_desc* find_file_desc(struct thread *t, int fd, enum fd_search_filter flag){
  ASSERT (t != NULL);

  if (fd < 3) {
    return NULL;
  }

  struct list_elem *e;

  if (! list_empty(&t->file_des)) {
    for(e = list_begin(&t->file_des); e != list_end(&t->file_des); e = list_next(e))
    {
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if(desc->id == fd) {
       
        if (desc->dir != NULL && (flag & FD_DIRECTORY) )
	  return desc;
        else if (desc->dir == NULL && (flag & FD_FILE) )
          return desc;
      }
    }
  }

  return NULL; // not found
}
#ifdef VM
//降序查找内存映射
static struct mmap_desc *find_mmap_desc(struct thread *t,mmapid_t mpid){
	ASSERT(t!=NULL);
	struct list_elem *l;
	if(!list_empty(&t->map_list)){
	  for(l=list_begin(&t->map_list);l!=list_end(&t->map_list);l=list_next(l)){
		struct mmap_desc *d=list_entry(l,struct mmap_desc,elem);
		if(d->id==mpid){
			return d;		
		}
	  }
	}
	return NULL;
}
//设置内存映射
mmapid_t _mmap(int fd,void *up){
	if(up==NULL||pg_ofs(up)!=0) return -1;
	if(fd<-1) return -1;
	struct thread *cur=thread_current();
	lock_acquire(&filesys_lock);
	//
	struct file *f=NULL;
	struct file_desc* f_desc=find_file_desc(cur,fd,FD_FILE);
	if(f_desc&&f_desc->file){
		f=file_reopen(f_desc->file);
	}
	
	if(f==NULL) {
		lock_release(&filesys_lock);
		return -1;	
	}
	size_t f_size=file_length(f);
	if(f_size==0){
		lock_release(&filesys_lock);
		return -1;	
	}
	size_t i;
	for(i=0;i<f_size;i+=PGSIZE){
		void *addr=up+i;
		if(pgtab_entry(cur->page_table,addr)){
			lock_release(&filesys_lock);
			return -1;	
		}
	}

	for(i=0;i<f_size;i+=PGSIZE){
		void *addr=up+i;
		size_t read=(i+PGSIZE<f_size ? PGSIZE:f_size-i);
		size_t unread=PGSIZE-read;
		pgtab_loadfilesys(cur->page_table,addr,f,i,read,unread, true);
	}

	mmapid_t m;
	if(!list_empty(&cur->map_list)){
		m=list_entry(list_back(&cur->map_list),struct mmap_desc,elem)->id+1;		
	}
	else m=1;
	struct mmap_desc *mmd=(struct mmap_desc*)malloc(sizeof(struct mmap_desc));
	mmd->id=m;
	mmd->file=f;
	mmd->addr=up;
	mmd->size=f_size;
	list_push_back(&cur->map_list,&mmd->elem);
	lock_release(&filesys_lock);
	return m;

}
//解映射
bool _munmap(mmapid_t m){
	struct thread *cur=thread_current();
	struct mmap_desc *mmd=find_mmap_desc(cur,m);
	if(mmd==NULL) {return false;}
	lock_acquire(&filesys_lock);
	{size_t i,f_size=mmd->size;
	for(i=0;i<f_size;i+=PGSIZE){
		void *addr=mmd->addr+i;
		size_t bt=(i+PGSIZE<f_size ? PGSIZE:f_size-i);
	    pgtab_mm_unmap(cur->page_table,cur->pdir,addr,mmd->file,i,bt);
	}
	list_remove(&mmd->elem);
	file_close(mmd->file);
	free(mmd);
	}
	lock_release(&filesys_lock);
	return true;
}
//加载锁页
void load_hook_page(const void *buffer,size_t size){
	struct page_table *page_tab=thread_current()->page_table;
	uint32_t *pdir=thread_current()->pdir;
	void *up;
	for(up=pg_round_down(buffer);up<buffer+size;up+=PGSIZE){
		pgtab_loadpage(page_tab,pdir,up);
		pgtab_hook(page_tab,up);
	}
}
//加载wei锁页
void load_unhook_page(const void *buf,size_t size){
	struct page_table *page_tab=thread_current()->page_table;
	void *up;
	for(up=pg_round_down(buf);up<buf+size;up+=PGSIZE){
		pgtab_unhook(page_tab,up);
	}
}
#endif
#ifdef FILESYS
bool _chdir(const char *f){
	bool re;
	mem_check((const uint8_t*)f);
	
	lock_acquire(&filesys_lock);
	re=filesys_chdir(f);
	lock_release(&filesys_lock);
	return re;
}
bool _mkdir(const char *f){
	bool re;
	mem_check((const uint8_t*)f);
	
	lock_acquire(&filesys_lock);
	re=filesys_create(f,0,true);
	lock_release(&filesys_lock);
	return re;
}
bool _readdir(int fd, char *n){
	struct file_desc* f_d;
	bool re=false;
	lock_acquire(&filesys_lock);
	f_d=find_file_desc(thread_current(),fd,FD_DIRECTORY);
	if(f_d==NULL) {
		lock_release(&filesys_lock);
		return re;
	}
	struct inode *ind;
	ind=file_get_inode(f_d->file);
	if(ind==NULL){
		lock_release(&filesys_lock);
		return re;	
	}
	if(!inode_isdir(ind)){
		lock_release(&filesys_lock);
		return re;	
	}
	ASSERT(f_d->dir!=NULL);
	re=dir_readdir(f_d->dir,n);
	lock_release(&filesys_lock);
	return re;
}
bool _isdir(int fd){
	lock_acquire(&filesys_lock);
	struct file_desc *f_d=find_file_desc(thread_current(),fd,FD_FILE|FD_DIRECTORY);
	struct inode *i=file_get_inode(f_d->file);
	bool re=inode_isdir(i);
	lock_release(&filesys_lock);
	return re;
}
int _inodenum(int fd){
	lock_acquire(&filesys_lock);
	struct file_desc *f=find_file_desc(thread_current(),fd,FD_FILE|FD_DIRECTORY);
	int re=(int)inode_get_inumber(file_get_inode(f->file));
	lock_release(&filesys_lock);
	return re;
}
#endif
