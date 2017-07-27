#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/message.h>  // for mach_msg_type_number_t
#include <mach/task_info.h>
#elif defined(__sun__)
#include <procfs.h>
#include <fcntl.h>
#endif

#ifdef __CYGWIN__
#define PAGE_SIZE 65536
#else
#define PAGE_SIZE 4096
#endif

long long prev_resident = 0;
long long cur_resident = 0;

#ifdef __APPLE__
static
void update_usage(void)
{
	mach_msg_type_number_t outCount;
	mach_task_basic_info_data_t taskinfo;

	taskinfo.virtual_size = 0;
	outCount = MACH_TASK_BASIC_INFO_COUNT;
	task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&taskinfo, &outCount);

	prev_resident = cur_resident;
	cur_resident = taskinfo.resident_size;
}
#elif defined(__sun__)
static
void update_usage(void)
{
	char psfile[64];
	pid_t pid;
	int fd;
	psinfo_t psinfo;

	pid = getpid();

	sprintf(psfile, "/proc/%d/psinfo", pid);

	fd = open(psfile, O_RDONLY);
	read(fd, &psinfo, sizeof(psinfo_t));
	close(fd);

	prev_resident = cur_resident;
	cur_resident = psinfo.pr_rssize * 1024;
}
#else
typedef struct {
    long size,resident,share,text,lib,data,dt;
} statm_t;

static
void update_usage(void)
{
	FILE *fp;
	statm_t result;

	fp = fopen("/proc/self/statm", "r");

	fscanf(fp, "%ld %ld %ld %ld %ld %ld %ld",
			&result.size,
			&result.resident,
			&result.share,
			&result.text,
			&result.lib,
			&result.data,
			&result.dt);

	prev_resident = cur_resident;
	cur_resident = result.resident * PAGE_SIZE;
}
#endif

static
void print_usage(void)
{
	update_usage();
	printf("  Resident memory variation: %lld kB\n", (cur_resident - prev_resident) / 1024);
}

void *global_mmap(size_t length)
{
	void *addr;

	addr = mmap(NULL, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		perror("mmap:");
		exit(1);
	}

	printf("Mapped %zu kB at %p\n", length / 1024, addr);
	print_usage();

	return addr;
}

static
void global_munmap(void *addr, size_t length)
{
	int ret;

	ret = munmap(addr, length);
	if (ret != 0) {
		perror("munmap:");
		exit(1);
	}

	printf("Unmapped global mapping\n");
	print_usage();
}

static
void *allocate_chunks_mprotect(void *chunk_addr, size_t chunk_len, size_t count)
{
	int ret;

	for (int i = 0; i<count; i++) {
		ret = mprotect(chunk_addr, chunk_len, PROT_READ | PROT_WRITE);
		if (ret != 0) {
			perror("mprotect");
			exit(1);
		}

		memset(chunk_addr, 1, chunk_len);
		chunk_addr += chunk_len;
	}

	printf("Allocated %zu chunks of memory with mprotect\n", count);
	print_usage();

	return chunk_addr;
}

static
void *deallocate_chunks_mprotect(void *chunk_addr, size_t chunk_len, size_t count, bool madv)
{
	int ret;

	for (int i = count; i>0; i--) {
		chunk_addr -= chunk_len;

		ret = mprotect(chunk_addr, chunk_len, PROT_NONE);
		if (ret != 0) {
			perror("mprotect");
			exit(1);
		}
		if (madv) {
			ret = madvise(chunk_addr, chunk_len, MADV_DONTNEED);
			if (ret != 0) {
				perror("madvise");
				exit(1);
			}
		}
	}

	printf("Deallocated %zu chunks of memory with mprotect\n", count);
	print_usage();

	return chunk_addr;
}

static
void *allocate_chunks_mmap(void *chunk_addr, size_t chunk_len, size_t count)
{
	void *ret_addr;

	for (int i = 0; i<count; i++) {
		ret_addr = mmap(chunk_addr, chunk_len, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (ret_addr == MAP_FAILED) {
			perror("mmap");
			exit(1);
		}

		memset(chunk_addr, 1, chunk_len);

		chunk_addr += chunk_len;
	}

	printf("Allocated %zu chunks of memory with overlapping mmap\n", count);
	print_usage();

	return chunk_addr;
}

static
void *deallocate_chunks_mmap(void *chunk_addr, size_t chunk_len, size_t count, bool madv)
{
	void *ret_addr;
	int ret;

	for (int i = count; i>0; i--) {
		chunk_addr -= chunk_len;

		ret_addr = mmap(chunk_addr, chunk_len, PROT_NONE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (ret_addr == MAP_FAILED) {
			perror("mmap");
			exit(1);
		}
		ret = madvise(chunk_addr, chunk_len, MADV_DONTNEED);
		if (ret != 0) {
			perror("madvise");
			exit(1);
		}
	}

	printf("Deallocated %zu chunks of memory with overlapping mmap\n", count);
	print_usage();

	return chunk_addr;
}

static
void sliding_mprotect(void *chunk_addr, size_t chunk_len, size_t count, bool madv)
{
	void *prev_chunk = NULL;
	void *new_chunk = chunk_addr;

	for (int i = 0; i<count; i++) {
		if (prev_chunk != NULL) {
			deallocate_chunks_mprotect(prev_chunk, chunk_len, 1, madv);
		}
		prev_chunk = new_chunk + chunk_len;
		new_chunk = allocate_chunks_mprotect(new_chunk, chunk_len, 1);
	}
}

static
void sliding_mmap(void *chunk_addr, size_t chunk_len, size_t count, bool madv)
{
	void *prev_chunk = NULL;
	void *new_chunk = chunk_addr;

	for (int i = 0; i<count; i++) {
		if (prev_chunk != NULL) {
			deallocate_chunks_mmap(prev_chunk, chunk_len, 1, madv);
		}
		prev_chunk = new_chunk + chunk_len;
		new_chunk = allocate_chunks_mmap(new_chunk, chunk_len, 1);
	}
}

int main()
{
	void *addr;
	size_t len = 419430400; // 400 MB
	size_t chunk_len = 1048576; // 1 MB
	size_t count = 50;

	update_usage();

	printf("Test with mprotect:\n");
	addr = global_mmap(len);
	addr = allocate_chunks_mprotect(addr, chunk_len, count);
	addr = deallocate_chunks_mprotect(addr, chunk_len, count, false);
	global_munmap(addr, len);


	printf("\n\nTest with mprotect and madvise:\n");
	addr = global_mmap(len);
	addr = allocate_chunks_mprotect(addr, chunk_len, count);
	addr = deallocate_chunks_mprotect(addr, chunk_len, count, true);
	global_munmap(addr, len);


	printf("\n\nTest with overlapping mmap:\n");
	addr = global_mmap(len);
	addr = allocate_chunks_mmap(addr, chunk_len, count);
	addr = deallocate_chunks_mmap(addr, chunk_len, count, false);
	global_munmap(addr, len);


	len = 1099511627776; // 1 TB
	chunk_len = 1073741824; // 1 GB

	printf("\n\nTest with mprotect sliding window:\n");
	addr = global_mmap(len);
	sliding_mprotect(addr, chunk_len, count, true);
	global_munmap(addr, len);


	printf("\n\nTest with mmap sliding window:\n");
	addr = global_mmap(len);
	sliding_mmap(addr, chunk_len, count, false);
	global_munmap(addr, len);

	return 0;
}
