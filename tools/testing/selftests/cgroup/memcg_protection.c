// SPDX-License-Identifier: GPL-2.0
/*
 * Reclaim tests for the memory protection backport.
 *
 * Run only in a disposable VM: these tests change the global cgroup2
 * mount options and deliberately provoke a confined memcg OOM kill.
 * Pass a directory on a real, writable filesystem for page-cache data.
 * Run the v1 fixture in a separate boot with MEMCG_TEST_V1_ONLY=1.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <unistd.h>

#define MB(n) ((long long)(n) << 20)
#define CG "/tmp/memcg-protection"
#define NSCG CG "-ns"
#define TOP CG "/a"
#define GROUP TOP "/b"
#define PRESSURE TOP "/g"
#define LEAF GROUP "/c"
#define OTHER GROUP "/d"
#define EMPTY GROUP "/e"
#define FREE GROUP "/f"

static unsigned int nr_tests, nr_failed, file_id;
static const char *data_dir;
static pid_t children[16];
static unsigned int nr_children;

static void result(bool ok, const char *name)
{
	printf("%s %u - %s\n", ok ? "ok" : "not ok", ++nr_tests, name);
	nr_failed += !ok;
}

static int write_value(const char *dir, const char *file, const char *value)
{
	char path[PATH_MAX];
	int fd, ret, saved;

	snprintf(path, sizeof(path), "%s/%s", dir, file);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ret = write(fd, value, strlen(value)) == (ssize_t)strlen(value) ?
		0 : -1;
	saved = errno;
	close(fd);
	errno = saved;
	return ret;
}

static long long read_value(const char *dir, const char *file,
			    const char *key)
{
	char path[PATH_MAX], buf[4096], *p;
	int fd;
	ssize_t n;

	snprintf(path, sizeof(path), "%s/%s", dir, file);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	p = key ? strstr(buf, key) : buf;
	if (p && !strcmp(p, "max\n"))
		return LLONG_MAX;
	return p ? strtoll(p + (key ? strlen(key) : 0), NULL, 10) : -1;
}

static bool mount_has_option(void)
{
	char line[4096];
	FILE *f = fopen("/proc/mounts", "r");
	bool found = false;

	if (!f)
		return false;
	while (fgets(line, sizeof(line), f))
		if (strstr(line, " " CG " cgroup2 "))
			found = strstr(line, "memory_recursiveprot") != NULL;
	fclose(f);
	return found;
}

static int remount(bool recursive)
{
	return mount("none", CG, "cgroup2", MS_REMOUNT,
		     recursive ? "memory_recursiveprot" : "");
}

static int group(const char *path, bool branch)
{
	if (mkdir(path, 0755))
		return -1;
	if (branch)
		return write_value(path, "cgroup.subtree_control", "+memory");
	return 0;
}

static int setup_tree(bool recursive, const char *kind)
{
	if (remount(recursive) || group(TOP, true) ||
	    write_value(TOP, "memory.max", "200M") ||
	    write_value(TOP, "memory.swap.max", "0") ||
	    group(GROUP, true) || group(PRESSURE, false) ||
	    group(LEAF, false) || group(OTHER, false) ||
	    group(EMPTY, false) || group(FREE, false))
		return -1;
	return write_value(GROUP, kind, "50M");
}

static void stop_children(void)
{
	while (nr_children) {
		pid_t pid = children[--nr_children];

		kill(pid, SIGKILL);
		while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
			;
	}
}

static void cleanup(void)
{
	const char *dirs[] = { LEAF, OTHER, EMPTY, FREE,
			      GROUP, PRESSURE, TOP };
	unsigned int i;

	stop_children();
	for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
		rmdir(dirs[i]);
}

/* Return a stopped worker's wait status, or -1 once it is ready. */
static int worker(const char *cg, unsigned int megabytes, bool cache)
{
	char path[PATH_MAX];
	int pipefd[2], status;
	char ready;
	pid_t pid;

	snprintf(path, sizeof(path), "%s/memcg-cache-%u",
		 data_dir, file_id++);
	if (pipe(pipefd))
		return 255 << 8;
	pid = fork();
	if (!pid) {
		char *buf;
		size_t size = (size_t)MB(megabytes), i;
		int fd = -1;
		size_t page_size = sysconf(_SC_PAGESIZE);

		close(pipefd[0]);
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		alarm(40);
		if (write_value(cg, "cgroup.procs", "0"))
			_exit(2);
		if (cache) {
			fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
			if (fd < 0 || unlink(path) || ftruncate(fd, size))
				_exit(3);
		} else {
			/* Keep OOM victims in the pressure group. */
			if (write_value("/proc/self", "oom_score_adj", "1000"))
				_exit(4);
		}
		if (cache) {
			char block[4096];

			/* Read cold cache, as in the upstream test. */
			for (i = 0; i < size; i += sizeof(block))
				if (pread(fd, block, sizeof(block), i) !=
				    sizeof(block))
					_exit(6);
		} else {
			buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (buf == MAP_FAILED)
				_exit(5);
			for (i = 0; i < size; i += page_size)
				*(volatile char *)(buf + i) = 1;
		}
		if (write(pipefd[1], "R", 1) != 1)
			_exit(7);
		close(pipefd[1]);
		alarm(0);
		for (;;)
			pause();
	}
	close(pipefd[1]);
	if (pid < 0) {
		close(pipefd[0]);
		return 255 << 8;
	}
	if (read(pipefd[0], &ready, 1) == 1 && ready == 'R') {
		children[nr_children++] = pid;
		close(pipefd[0]);
		return -1;
	}
	close(pipefd[0]);
	waitpid(pid, &status, 0);
	printf("# allocation in %s exited with wait status %d\n", cg, status);
	return status;
}

static void interfaces(void)
{
	bool ok;

	ok = !group(TOP, false) &&
	     read_value(TOP, "memory.min", NULL) == 0 &&
	     read_value(TOP, "memory.low", NULL) == 0 &&
	     !write_value(TOP, "memory.min", "8M") &&
	     read_value(TOP, "memory.min", NULL) == MB(8) &&
	     write_value(TOP, "memory.min", "invalid") == -1 &&
	     read_value(TOP, "memory.min", NULL) == MB(8) &&
	     !write_value(TOP, "memory.min", "max") &&
	     read_value(TOP, "memory.min", NULL) > MB(1024);
	result(ok, "memory.min defaults to zero and validates writes");
	cleanup();
}

static void inheritance(bool recursive)
{
	long long kept = -1, unprotected = -1;
	bool ok = !setup_tree(recursive, "memory.low");

	ok = ok && worker(LEAF, 50, true) == -1 &&
	     worker(PRESSURE, 50, true) == -1 &&
	     worker(PRESSURE, 145, false) == -1;
	if (ok) {
		usleep(200000);
		kept = read_value(LEAF, "memory.stat", "file ");
		unprotected = read_value(PRESSURE, "memory.stat", "file ");
		printf("# recursive=%d: protected=%lld, outside=%lld\n",
		       recursive, kept, unprotected);
		if (recursive)
			ok = kept > MB(45) && unprotected < MB(8);
		else
			ok = kept > MB(5) && kept < MB(43) &&
			     unprotected > MB(5);
	}
	result(ok, recursive ? "parent low protects zero-low descendants" :
			       "plain mount retains non-recursive protection");
	cleanup();
}

/*
 * The 50/75/25 MiB hierarchy follows Roman Gushchin's upstream
 * test_memcontrol.c. Unequal protection must survive limit reclaim.
 */
static void proportional(const char *kind)
{
	long long c = -1, d = -1, e = -1, total = -1;
	bool hard = !strcmp(kind, "memory.min");
	bool ok = !setup_tree(true, kind);
	int status;

	ok = ok && !write_value(LEAF, kind, "75M") &&
	     !write_value(OTHER, kind, "25M") &&
	     !write_value(EMPTY, kind, "500M") &&
	     worker(LEAF, 50, true) == -1 &&
	     worker(OTHER, 50, true) == -1 &&
	     worker(FREE, 50, true) == -1 &&
	     worker(PRESSURE, 148, false) == -1;
	if (ok) {
		usleep(200000);
		c = read_value(LEAF, "memory.stat", "file ");
		d = read_value(OTHER, "memory.stat", "file ");
		e = read_value(EMPTY, "memory.current", NULL);
		total = read_value(GROUP, "memory.current", NULL);
		printf("# %s overcommit: c=%lld d=%lld empty=%lld total=%lld\n",
		       kind, c, d, e, total);
		ok = c > MB(25) && c < MB(40) &&
		     d > MB(10) && d < MB(24) && e == 0 &&
		     total > MB(45) && total < MB(58);
	}
	result(ok, hard ? "overcommitted min is shared proportionally" :
			  "overcommitted low is shared proportionally");
	if (ok) {
		/* Raise pressure from 148 MiB to 170 MiB. */
		kill(children[--nr_children], SIGKILL);
		waitpid(children[nr_children], NULL, 0);
		status = worker(PRESSURE, 170, false);
		if (hard)
			ok = status >= 0 && WIFSIGNALED(status) &&
			     WTERMSIG(status) == SIGKILL &&
			     read_value(GROUP, "memory.current", NULL) >
			     MB(45) &&
			     read_value(TOP, "memory.events", "oom ") > 0;
		else
			ok = status == -1 &&
			     read_value(GROUP, "memory.current", NULL) <
			     MB(32) &&
			     read_value(LEAF, "memory.events", "low ") > 0 &&
			     read_value(TOP, "memory.events", "oom ") == 0;
	}
	result(ok, hard ? "memory.min survives a confined memcg OOM" :
			  "memory.low yields before OOM");
	cleanup();
}

static void local_limit(void)
{
	bool ok = !setup_tree(true, "memory.min");
	long long before = -1, after = -1;

	/* Outside pressure first sets the child's inherited emin. */
	ok = ok && worker(LEAF, 50, true) == -1 &&
	     worker(PRESSURE, 50, true) == -1 &&
	     worker(PRESSURE, 145, false) == -1;
	if (ok) {
		before = read_value(LEAF, "memory.current", NULL);
		ok = !write_value(LEAF, "memory.max", "15M");
		after = read_value(LEAF, "memory.current", NULL);
		printf("# target reclaim: before=%lld after=%lld\n",
		       before, after);
		ok = ok && before > MB(45) && after <= MB(15) &&
		     read_value(TOP, "memory.events", "oom ") == 0;
	}
	result(ok, "targeted reclaim ignores stale inherited protection");
	cleanup();
}

static void namespace_options(void)
{
	pid_t pid;
	int status;
	bool ok = !remount(true);

	mkdir(NSCG, 0755);
	pid = fork();
	if (!pid) {
		if (unshare(CLONE_NEWCGROUP | CLONE_NEWNS) ||
		    mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) ||
		    mount("none", NSCG, "cgroup2", 0, "") ||
		    mount("none", NSCG, "cgroup2",
			  MS_REMOUNT, ""))
			_exit(1);
		_exit(0);
	}
	if (pid < 0 || waitpid(pid, &status, 0) < 0)
		ok = false;
	else
		ok = ok && WIFEXITED(status) && !WEXITSTATUS(status);
	result(ok && mount_has_option(),
	       "nested namespaces cannot clear recursive protection");
	rmdir(NSCG);
}

static void stress(void)
{
	pid_t writer;
	int i, status;
	bool ok = !setup_tree(true, "memory.low");

	ok = ok && !write_value(TOP, "memory.max", "120M") &&
	     worker(PRESSURE, 60, false) == -1;
	writer = ok ? fork() : -1;
	if (!writer) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		for (i = 0; i < 10000; i++) {
			if (write_value(GROUP, "memory.low",
					i & 1 ? "50M" : "0") ||
			    write_value(GROUP, "memory.min",
					i & 1 ? "8M" : "0") ||
			    write_value(LEAF, "memory.low",
					i & 1 ? "32M" : "0"))
				_exit(1);
		}
		_exit(0);
	}
	if (writer < 0)
		ok = false;
	for (i = 0; ok && i < 20; i++) {
		ok = worker(LEAF, 64, true) == -1;
		if (ok) {
			kill(children[--nr_children], SIGKILL);
			waitpid(children[nr_children], NULL, 0);
			ok = !group(GROUP "/transient", false) &&
			     !write_value(GROUP "/transient",
					  "memory.low", "16M") &&
			     worker(GROUP "/transient", 4, true) == -1;
			if (ok) {
				kill(children[--nr_children], SIGKILL);
				waitpid(children[nr_children], NULL, 0);
				ok = !rmdir(GROUP "/transient");
			}
		}
	}
	if (writer > 0) {
		if (!ok)
			kill(writer, SIGKILL);
		waitpid(writer, &status, 0);
		ok = ok && WIFEXITED(status) && !WEXITSTATUS(status);
	}
	result(ok && read_value(TOP, "memory.events", "oom ") == 0,
	       "concurrent protection updates, reclaim and group teardown");
	stop_children();
	rmdir(GROUP "/transient");
	cleanup();
}

static void legacy(void)
{
	bool ok = !mount("none", CG, "cgroup", 0, "memory");

	ok = ok && !mkdir(TOP, 0755) &&
	     !write_value(TOP, "memory.use_hierarchy", "1") &&
	     !write_value(TOP, "memory.limit_in_bytes", "24M") &&
	     worker(TOP, 8, false) == -1 &&
	     read_value(TOP, "memory.usage_in_bytes", NULL) >= MB(8) &&
	     read_value(TOP, "memory.limit_in_bytes", NULL) == MB(24) &&
	     write_value(TOP, "memory.limit_in_bytes", "4M") == -1;
	result(ok, "v1 memory charging and limits remain functional");
	cleanup();
	umount(CG);
}

int main(int argc, char **argv)
{
	struct statfs fs;
	const char *isolated = getenv("MEMCG_TEST_ISOLATED");
	int i;
	bool ok;

	setbuf(stdout, NULL);
	puts("TAP version 13");
	if (!isolated || strcmp(isolated, "1") || geteuid() || argc != 2) {
		puts("1..0 # SKIP disposable VM and cache directory required");
		return 4;
	}
	data_dir = argv[1];
	if (statfs(data_dir, &fs) || fs.f_type == 0x01021994 ||
	    fs.f_type == 0x858458f6) {
		puts("Bail out! Use a disk-backed filesystem, not tmpfs/ramfs");
		return 1;
	}
	alarm(240);
	if (mkdir(CG, 0755)) {
		perror("create mountpoint");
		return 1;
	}
	if (getenv("MEMCG_TEST_V1_ONLY")) {
		legacy();
		goto out;
	}
	ok = mount("none", CG, "cgroup2", 0, "not_a_cgroup_option") == -1 &&
	     errno == EINVAL && !mount("none", CG, "cgroup2", 0, "");
	result(ok && !mount_has_option(),
	       "plain mount and invalid option handling");
	if (!ok)
		goto out;
	ok = !umount(CG) &&
	     !mount("none", CG, "cgroup2", 0, "memory_recursiveprot");
	result(ok && mount_has_option(), "initial recursive mount succeeds");
	if (!ok)
		goto out;
	ok = !remount(true) && mount_has_option() &&
	     mount("none", CG, "cgroup2", MS_REMOUNT, "invalid") == -1 &&
	     mount_has_option() && !remount(false) && !mount_has_option();
	result(ok, "recursive protection remount and option reporting");
	if (!ok)
		goto out;
	for (i = 0; i < 100; i++) {
		if (!write_value(CG, "cgroup.subtree_control", "+memory"))
			break;
		usleep(100000);
	}
	if (i == 100) {
		result(false, "memory controller available on v2");
		goto out;
	}
	interfaces();
	namespace_options();
	inheritance(false);
	inheritance(true);
	proportional("memory.low");
	proportional("memory.min");
	local_limit();
	stress();
out:
	cleanup();
	umount(CG);
	rmdir(CG);
	printf("1..%u\n", nr_tests);
	return nr_failed ? 1 : 0;
}
