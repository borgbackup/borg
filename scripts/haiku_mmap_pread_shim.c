/*
 * haiku_mmap_pread_shim: LD_PRELOAD workaround for the Haiku file cache bug
 * https://dev.haiku-os.org/ticket/20392 (also see
 * https://github.com/cross-platform-actions/haiku-builder/issues/4).
 *
 * A write() whose source buffer is a file mapping can store stale pages in the
 * destination file. This shim replaces private mappings of regular files by
 * anonymous memory filled with pread(), so such a write() reads from ordinary
 * memory instead of from file cache pages.
 *
 * Not replaced (passed through to the real mmap()):
 *   - MAP_SHARED mappings (writes must reach the file),
 *   - anonymous mappings,
 *   - executable mappings,
 *   - anything that is not a regular file.
 *
 * Differences to a real private file mapping: the whole range is read at
 * mmap() time and uses memory of its own, and later changes of the file are
 * not visible in the mapping.
 *
 * Build:  gcc -O2 -Wall -shared -fPIC -o haiku_mmap_pread_shim.so haiku_mmap_pread_shim.c
 * Use:    LD_PRELOAD=/path/to/haiku_mmap_pread_shim.so <command>
 * Debug:  HAIKU_MMAP_PREAD_SHIM_DEBUG=1 prints one line per replaced mapping.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

typedef void *(*mmap_func)(void *, size_t, int, int, int, off_t);

static mmap_func real_mmap;
static int debug = -1;

void *
mmap(void *address, size_t length, int protection, int flags, int fd,
	off_t offset)
{
	if (real_mmap == NULL)
		real_mmap = (mmap_func)dlsym(RTLD_NEXT, "mmap");
	if (real_mmap == NULL) {
		errno = ENOSYS;
		return MAP_FAILED;
	}

	struct stat st;
	if (fd < 0 || length == 0 || offset < 0
		|| (flags & (MAP_SHARED | MAP_ANONYMOUS)) != 0
		|| (flags & MAP_PRIVATE) == 0
		|| (protection & PROT_EXEC) != 0
		|| fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		return real_mmap(address, length, protection, flags, fd, offset);
	}

	void *memory = real_mmap(address, length, PROT_READ | PROT_WRITE,
		flags | MAP_ANONYMOUS, -1, 0);
	if (memory == MAP_FAILED)
		return MAP_FAILED;

	// Fill the memory from the file. Whatever is beyond the end of the file
	// stays zero, like in a real mapping of the last file page.
	size_t done = 0;
	while (done < length) {
		ssize_t bytesRead = pread(fd, (char *)memory + done, length - done,
			offset + (off_t)done);
		if (bytesRead < 0) {
			if (errno == EINTR)
				continue;
			int error = errno;
			munmap(memory, length);
			errno = error;
			return MAP_FAILED;
		}
		if (bytesRead == 0)
			break;
		done += (size_t)bytesRead;
	}

	if ((protection & PROT_WRITE) == 0
		&& mprotect(memory, length, protection) != 0) {
		int error = errno;
		munmap(memory, length);
		errno = error;
		return MAP_FAILED;
	}

	if (debug < 0)
		debug = getenv("HAIKU_MMAP_PREAD_SHIM_DEBUG") != NULL;
	if (debug) {
		char line[128];
		int size = snprintf(line, sizeof(line),
			"haiku_mmap_pread_shim: fd %d offset %lld length %zu -> %p\n", fd,
			(long long)offset, length, memory);
		if (size > 0)
			write(STDERR_FILENO, line, (size_t)size);
	}

	return memory;
}
