// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_process_mrelease
#define __NR_process_mrelease 448
#endif

#define LENGTH (16UL << 20)
#define ITERATIONS 64
static unsigned int passed, failed;
static size_t pagesize;

static long release(int fd, unsigned int flags)
{
	return syscall(__NR_process_mrelease, fd, flags);
}

static int pidfd(pid_t pid)
{
	return syscall(__NR_pidfd_open, pid, 0);
}

static void check(bool ok, const char *name)
{
	printf("%s %u - %s\n", ok ? "ok" : "not ok",
	       passed + failed + 1, name);
	if (ok)
		passed++;
	else
		failed++;
}

static void fatal(const char *name)
{
	perror(name);
	exit(1);
}

static char *mapping(size_t size)
{
	char *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		fatal("mmap");
	return p;
}

static int wait_child(pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR)
			fatal("waitpid");
	}
	return status;
}

static char state(pid_t pid)
{
	char path[64], line[256], result = '?';
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "r");
	if (!f)
		return result;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "State: %c", &result) == 1)
			break;
	fclose(f);
	return result;
}

static void *churn(void *unused)
{
	(void)unused;
	for (;;) {
		char *p = mapping(pagesize * 16);

		memset(p, 0xa5, pagesize * 16);
		if (mprotect(p, pagesize * 8, PROT_READ))
			_exit(2);
		munmap(p, pagesize * 16);
	}
	return NULL;
}

static void *park(void *unused)
{
	(void)unused;
	for (;;)
		pause();
	return NULL;
}

static void reap_races(void)
{
	char *p = mapping(LENGTH);
	unsigned int reaped = 0, gone = 0, bad = 0, i;
	bool live_ok = true, stale_ok = true, exit_ok = true;

	memset(p, 0x5a, LENGTH);
	for (i = 0; i < ITERATIONS; i++) {
		int ready[2], fd, status, saved;
		pid_t pid;
		pthread_t worker;
		char byte;
		long ret;

		if (pipe(ready))
			fatal("pipe");
		pid = fork();
		if (pid < 0)
			fatal("fork");
		if (!pid) {
			prctl(PR_SET_PDEATHSIG, SIGKILL);
			alarm(20);
			close(ready[0]);
			memset(p, 0xa5, LENGTH);
			if (pthread_create(&worker, NULL, churn, NULL))
				_exit(2);
			if (write(ready[1], "R", 1) != 1)
				_exit(2);
			for (;;)
				pause();
		}
		close(ready[1]);
		if (read(ready[0], &byte, 1) != 1)
			fatal("child readiness");
		close(ready[0]);
		fd = pidfd(pid);
		if (fd < 0)
			fatal("pidfd_open");
		live_ok &= release(fd, 0) == -1 && errno == EINVAL;
		if (kill(pid, SIGKILL))
			fatal("kill");
		ret = release(fd, 0);
		saved = errno;
		if (!ret)
			reaped++;
		else if (ret == -1 && saved == ESRCH)
			gone++;
		else {
			printf("# race %u: ret=%ld errno=%d\n", i, ret, saved);
			bad++;
		}
		status = wait_child(pid);
		exit_ok &= WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
		stale_ok &= release(fd, 0) == -1 && errno == ESRCH;
		close(fd);
	}
	check(live_ok, "live processes reject memory release");
	check(!bad && reaped, "reap concurrently with mmap and process exit");
	check(exit_ok, "all race victims exit from SIGKILL");
	check(stale_ok, "reaped pidfds return ESRCH without PID reuse");
	for (i = 0; i < LENGTH; i++)
		if (p[i] != 0x5a)
			break;
	check(i == LENGTH, "reaping preserves the parent's COW data");
	printf("# races: %u completed, %u already exited, %u errors\n",
	       reaped, gone, bad);
	munmap(p, LENGTH);
}

static int shared_child(void *unused)
{
	(void)unused;
	alarm(20);
	for (;;)
		pause();
	return 0;
}

static void shared_mm(void)
{
	char *stack = mapping(1UL << 20), *p = mapping(LENGTH);
	pid_t pid;
	int fd, status;
	long ret;
	size_t i;

	memset(p, 0x3c, LENGTH);
	pid = clone(shared_child, stack + (1UL << 20), CLONE_VM | SIGCHLD,
		    NULL);
	if (pid < 0)
		fatal("clone");
	fd = pidfd(pid);
	if (fd < 0)
		fatal("pidfd_open");
	if (kill(pid, SIGKILL))
		fatal("kill shared child");
	ret = release(fd, 0);
	check(ret == -1 && (errno == EINVAL || errno == ESRCH),
	      "a dying process cannot reap a surviving process's shared mm");
	status = wait_child(pid);
	check(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
	      "shared-mm child exits normally after SIGKILL");
	for (i = 0; i < LENGTH; i++)
		if (p[i] != 0x3c)
			break;
	check(i == LENGTH, "the surviving address space remains intact");
	close(fd);
	munmap(stack, 1UL << 20);
	munmap(p, LENGTH);
}

static void exited_leader(void)
{
	pid_t pid = fork();
	int fd, i;
	long ret;

	if (pid < 0)
		fatal("fork");
	if (!pid) {
		pthread_t worker;

		alarm(20);
		if (pthread_create(&worker, NULL, park, NULL))
			_exit(2);
		syscall(SYS_exit, 0);
		_exit(2);
	}
	for (i = 0; i < 2000 && state(pid) != 'Z'; i++)
		usleep(1000);
	check(state(pid) == 'Z', "fixture has an exited thread-group leader");
	fd = pidfd(pid);
	if (fd < 0)
		fatal("pidfd_open exited leader");
	check(release(fd, 0) == -1 && errno == EINVAL,
	      "lookup finds a live thread after its group leader exits");
	if (kill(pid, SIGKILL))
		fatal("kill thread group");
	ret = release(fd, 0);
	check(!ret || (ret == -1 && errno == ESRCH),
	      "release accepts a dying group with an exited leader");
	wait_child(pid);
	close(fd);
}

int main(void)
{
	int fd;
	long ret;

	setbuf(stdout, NULL);
	printf("TAP version 13\n");
	ret = release(-1, 0);
	if (ret == -1 && errno == ENOSYS) {
		printf("1..0 # SKIP process_mrelease is unavailable\n");
		return 4;
	}
	check(ret == -1 && errno == EBADF, "invalid pidfd returns EBADF");
	check(release(-1, 1) == -1 && errno == EINVAL,
	      "reserved flags return EINVAL before fd lookup");
	pagesize = sysconf(_SC_PAGESIZE);
	fd = pidfd(getpid());
	if (fd < 0)
		fatal("pidfd_open self");
	check(release(fd, 0) == -1 && errno == EINVAL,
	      "a live caller cannot reap itself");
	close(fd);
	exited_leader();
	shared_mm();
	reap_races();
	printf("1..%u\n", passed + failed);
	return failed ? 1 : 0;
}
