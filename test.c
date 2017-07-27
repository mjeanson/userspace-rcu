#include <stdio.h>
#include <sys/mman.h>
#include <string.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/message.h>  // for mach_msg_type_number_t
#include <mach/task_info.h>
#elif defined(__sun__)
#include <unistd.h>
#include <procfs.h>
#include <fcntl.h>
#endif

#ifdef __CYGWIN__
#define GRAN 65536
#else
#define GRAN 4096
#endif

long resident = 0;

#ifdef __APPLE__
void print_usage() {
	mach_msg_type_number_t outCount;
	mach_task_basic_info_data_t taskinfo;

	taskinfo.virtual_size = 0;
	outCount = MACH_TASK_BASIC_INFO_COUNT;
	task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&taskinfo, &outCount);

	printf("  Resident memory variation: %ld kB\n", (long) (taskinfo.resident_size - resident) / 1024);
	resident = taskinfo.resident_size;
}
#elif defined(__sun__)
void print_usage() {
	char psfile[64];
	pid_t pid;
	int fd;
	psinfo_t psinfo;

	pid = getpid();

	sprintf(psfile, "/proc/%d/psinfo", pid);

	fd = open(psfile, O_RDONLY);
	read(fd, &psinfo, sizeof(psinfo_t));
	close(fd);

	printf("  Resident memory variation: %ld kB\n", (long) (psinfo.pr_rssize - resident));
	resident = psinfo.pr_rssize;
}
#else
typedef struct {
    long size,resident,share,text,lib,data,dt;
} statm_t;

void print_usage() {
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
	printf("  Resident memory variation: %ld kB\n", (result.resident - resident) * GRAN / 1024);
	resident = result.resident;
}
#endif

int main() {
	int ret = 0;
	void *addr;
	void *chunk_addr;
	void *ret_addr;
	size_t len = 1000 * GRAN;
	size_t chunk = 10 * GRAN;

	addr = mmap(NULL, len, PROT_NONE, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		perror("mmap:");
		return 1;
	}

	printf("Mapped %zu kB at %p\n", len / 1024, addr);
	print_usage();

	chunk_addr = addr + (10 * GRAN);

	for (int i = 0; i<50; i++) {
		ret = mprotect(chunk_addr, chunk, PROT_READ | PROT_WRITE);
		if (ret != 0) {
			perror("mprotect");
			return 1;
		}


		memset(chunk_addr, 1, chunk);

		chunk_addr += chunk;
	}

	printf("Filled 50 chunks of memory with mprotect\n");
	print_usage();

	for (int i = 50; i>0; i--) {
		chunk_addr -= chunk;

		ret = mprotect(chunk_addr, chunk, PROT_NONE);
		if (ret != 0) {
			perror("mprotect");
			return 1;
		}
		ret = madvise(chunk_addr, chunk, MADV_DONTNEED);
		if (ret != 0) {
			perror("madvise");
			return 1;
		}
	}

	printf("Deallocated 50 chunks of memory with mprotect\n");
	print_usage();

	ret = munmap(addr, len);
	if (ret != 0) {
		perror("munmap:");
		return 1;
	}
	printf("Unmapped global mapping\n");
	print_usage();



	addr = mmap(NULL, len, PROT_NONE, MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr == MAP_FAILED) {
		perror("mmap:");
		return 1;
	}

	printf("\n\nMapped %zu kB at %p\n", len / 1024, addr);
	print_usage();

	chunk_addr = addr + (10 * GRAN);

	for (int i = 0; i<50; i++) {
		ret_addr = mmap(chunk_addr, chunk, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (ret_addr == MAP_FAILED) {
			perror("mmap");
			return 1;
		}

		memset(chunk_addr, 1, chunk);

		chunk_addr += chunk;
	}

	printf("Filled 50 chunks of memory with overlapping mmap\n");
	print_usage();

	for (int i = 50; i>0; i--) {
		chunk_addr -= chunk;

		ret_addr = mmap(chunk_addr, chunk, PROT_NONE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (ret_addr == MAP_FAILED) {
			perror("mmap");
			return 1;
		}
		ret = madvise(chunk_addr, chunk, MADV_DONTNEED);
		if (ret != 0) {
			perror("madvise");
			return 1;
		}
	}

	printf("Deallocated 50 chunks of memory with overlapping mmap\n");
	print_usage();

	ret = munmap(addr, len);
	if (ret != 0) {
		perror("munmap:");
		return 1;
	}
	printf("Unmapped global mapping\n");
	print_usage();
	return 0;
}
