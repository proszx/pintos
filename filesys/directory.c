#include "threads/thread.h"
#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

/* A directory. */
struct dir
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

/* A single directory entry. */
struct dir_entry
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };


static bool dir_get (const struct dir *dir, const char *name,struct dir_entry *ep, off_t *ofsp);

/* Creates a directory with space for ENTRY_CNT entries in the given SECTOR.
   Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt)
{
  bool s = true;
  s = inode_create (sector, entry_cnt * sizeof (struct dir_entry), true);
  if(!s) return false;
  // dir条目是父目录; 做自我引用 执行dir_add（）时将设置实际的父目录
  struct dir *d = dir_open( inode_open(sector) );
  ASSERT (d != NULL);
  struct dir_entry e;
  e.inode_sector = sector;
  if (inode_write_at(d->inode, &e, sizeof e, 0) != sizeof e) {
    s = false;
  }
  dir_close (d);

  return s;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode)
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = sizeof (struct dir_entry); //0为父目录
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL;
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

//根据路径打开目录
struct dir *dir_open_path (const char *path){
	//拷贝路径
  int l = strlen(path);
  char s[l + 1];
  strlcpy(s, path, l + 1);
//路径处理 如果是主目录则调用root打开
  struct dir *curr;
  if(path[0] == '/') { 
    curr = dir_open_root();
  }
  else { // 否则 则从当前进程获取当前目录
    struct thread *t = thread_current();
    if (t->cwd == NULL) // 如果进程为空指向主目录
      curr = dir_open_root();
    else {
      curr = dir_reopen( t->cwd );
    }
  }

  //便利目录树
  char *token, *p;
  for (token = strtok_r(s, "/", &p); token != NULL;
       token = strtok_r(NULL, "/", &p))
  {
    struct inode *inode = NULL;
    if(! dir_lookup(curr, token, &inode)) {
      dir_close(curr);
      return NULL; 
    }

    struct dir *next = dir_open(inode);
    if(next == NULL) {
      dir_close(curr);
      return NULL;
    }
    dir_close(curr);
    curr = next;
  }


  if (inode_isremove(dir_get_inode(curr))) {
    dir_close(curr);
    return NULL;
  }

  return curr;
}


struct dir *dir_reopen (struct dir *dir){
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir)
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir)
{
  ASSERT (dir != NULL);
  return dir->inode;
}


//判断目录是否为空
bool dir_is_empty (const struct dir *dir){
  struct dir_entry e;
  off_t ofs;

  for (ofs = sizeof e; /* 0-pos is for parent directory */
       inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
  {
    if (e.in_use)
      return false;
  }
  return true;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode)
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (strcmp (name, ".") == 0) {
    *inode = inode_reopen (dir->inode);
  }
  else if (strcmp (name, "..") == 0) {
    inode_read_at (dir->inode, &e, sizeof e, 0);
    *inode = inode_open (e.inode_sector);
  }
  else if (dir_get(dir, name, &e, NULL)) {
    *inode = inode_open (e.inode_sector);
  }
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector INODE_SECTOR.
   If the file is a directory, IS_DIR is set to true.

   Returns true if sful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector, bool isdir)
{
  struct dir_entry e;
  off_t offset;
  bool s = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  //确认名字是否正确
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  //检查目录是否已经载入 true done
  if (dir_get(dir, name, NULL, NULL))
    goto done;

  // 更新子目录
  if (isdir)
  {
    struct dir *child_dir = dir_open( inode_open(inode_sector) );
    if(child_dir == NULL) goto done;
    e.inode_sector = inode_get_inumber( dir_get_inode(dir) );
    if (inode_write_at(child_dir->inode, &e, sizeof e, 0) != sizeof e) {
      dir_close (child_dir);
      goto done;
    }
    dir_close (child_dir);
  }

  //便利判断是否在使用
  for (offset = 0; inode_read_at (dir->inode, &e, sizeof e, offset) == sizeof e;offset += sizeof e)
    if (!e.in_use)
      break;

  //将使用状态置为true 之后写入
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  s = inode_write_at (dir->inode, &e, sizeof e, offset) == sizeof e;

 done:
  return s;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name)
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool s = false;
  off_t offset;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  //找到目录
  if (!dir_get(dir, name, &e, &offset))
    goto done;

  //打开inode节点表
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  //维护即将要移除的非空目录
  if (inode_isdir (inode)) {
    
    struct dir *target = dir_open (inode);
    bool is_empty = dir_is_empty (target);
    dir_close (target);
    if (! is_empty) goto done; 
  }

  //卸载目录表
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, offset) != sizeof e)
    goto done;

  //移除inode
  inode_remove (inode);
  s = true;

 done:
  inode_close (inode);
  return s;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e)
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        }
    }
  return false;
}

void split_path(const char *path,char *directory, char *filename){
  int l = strlen(path);
  char *s = (char*) malloc( sizeof(char) * (l + 1) );
  memcpy (s, path, sizeof(char) * (l + 1));

  // absolute path handling
  char *dir = directory;
  if(l > 0 && path[0] == '/') {
    if(dir) *dir++ = '/';
  }

  // 标识化
  char *token, *p, *last_token = "";
  for (token = strtok_r(s, "/", &p); token != NULL;
       token = strtok_r(NULL, "/", &p))
  {
    // 将last_token附加到目录中
    int tl = strlen (last_token);
    if (dir && tl > 0) {
      memcpy (dir, last_token, sizeof(char) * tl);
      dir[tl] = '/';
      dir += tl + 1;
    }

    last_token = token;
  }

  if(dir) *dir = '\0';
  memcpy (filename, last_token, sizeof(char) * (strlen(last_token) + 1));
  free (s);

}

static bool dir_get (const struct dir *dir, const char *name,struct dir_entry *ep, off_t *ofsp){
  struct dir_entry e;
  size_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = sizeof e; 
       inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use && !strcmp (name, e.name))
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

