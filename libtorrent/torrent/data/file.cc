#include "config.h"

#include "file.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

namespace torrent {

File::~File() {
  close();
}

bool File::open(const std::string& path,
		int flags,
		int mode) {
  close();

  int fd = ::open(path.c_str(), 
		  
		  (flags & in && flags & out ? O_RDWR :
		   (flags & in  ? O_RDONLY : 0) |
		   (flags & out ? O_WRONLY : 0)) |
		  
		  (flags & create    ? O_CREAT     : 0) |
		  (flags & truncate  ? O_TRUNC     : 0) |
		  (flags & nonblock  ? O_NONBLOCK  : 0) |
		  (flags & largefile ? O_LARGEFILE : 0),
		  
		  mode);
  
  if (fd == -1)
    return false;

  m_stat = new struct stat;
  m_path = path;
  m_flags = flags;

  if (fstat(m_fd, m_stat) == -1) {
    close();

    return false;
  }

  return true;
}

void File::close() {
  if (!is_open())
    return;

  ::close(m_fd);

  delete m_stat;

  m_fd = -1;
  m_stat = NULL;
  m_flags = 0;
  m_path = "";
}
  
bool File::set_size(uint64_t v) {
  if (!is_open())
    return false;

  return !ftruncate(m_fd, v);
}

int File::get_mode() {
  return is_open() ? m_stat->st_mode & (S_IRWXU | S_IRWXG | S_IRWXO) : 0;
}

int File::get_type() {
  if (!is_open())
    return 0;

  if (S_ISREG(m_stat->st_mode))
    return type_regular;

  else if (S_ISDIR(m_stat->st_mode))
    return type_directory;

  else if (S_ISCHR(m_stat->st_mode))
    return type_character;

  else if (S_ISBLK(m_stat->st_mode))
    return type_block;
  
  else if (S_ISFIFO(m_stat->st_mode))
    return type_fifo;

  else if (S_ISLNK(m_stat->st_mode))
    return type_link;

  else if (S_ISSOCK(m_stat->st_mode))
    return type_socket;

  else
    return 0;
}

uint64_t File::get_size() {
  return is_open() ? m_stat->st_size : 0;
}

FileChunk File::get_chunk(uint64_t offset,
			  unsigned int length,
			  bool wr,
			  bool rd) {
  if (!is_open())
    return FileChunk();

  uint64_t align = offset % getpagesize();

  char* ptr = (char*)mmap(NULL, length + align,
			  (m_flags & in ? PROT_READ : 0) | (m_flags & out ? PROT_WRITE : 0),
			  MAP_SHARED, m_fd, offset - align);

  
  if (ptr == MAP_FAILED)
    return FileChunk();
  else
    return FileChunk(ptr, ptr + align, length);
}

}

