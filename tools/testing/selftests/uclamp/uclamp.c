// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#define KEEP_ALL 0x18
#define CLAMP_MIN 0x20
#define CLAMP_MAX 0x40
#define CLAMPS (CLAMP_MIN | CLAMP_MAX)
#define RESET_ON_FORK 1
#define CGROUP_MAGIC 0x27e0eb

struct attr {
	uint32_t size, policy;
	uint64_t flags;
	int32_t nice;
	uint32_t priority;
	uint64_t runtime, deadline, period;
	uint32_t min, max;
};

static unsigned int checks;
static char root[256], parent[320], child[384];
static pid_t workers[4];
static int sysctl_changed, saved_min, saved_max;
static volatile sig_atomic_t stopping;

static void stop_worker(int sig)
{
	(void)sig;
	stopping = 1;
}

static int set_attr(pid_t pid, struct attr *a)
{
	return syscall(__NR_sched_setattr, pid, a, 0);
}

static int get_attr(pid_t pid, struct attr *a)
{
	memset(a, 0, sizeof(*a));
	return syscall(__NR_sched_getattr, pid, a, sizeof(*a), 0);
}

static int write_value(const char *dir, const char *name,
		       const char *value)
{
	char path[1024];
	int fd, ret, saved;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ret = write(fd, value, strlen(value));
	saved = errno;
	close(fd);
	errno = saved;
	return ret == (int)strlen(value) ? 0 : -1;
}

static int move_pid(const char *dir, pid_t pid)
{
	char value[32];

	snprintf(value, sizeof(value), "%d", pid);
	return write_value(dir, "tasks", value);
}

static int read_value(const char *dir, const char *name,
		      char *value, size_t size)
{
	char path[1024];
	int fd, ret;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ret = read(fd, value, size - 1);
	close(fd);
	if (ret < 0)
		return -1;
	value[ret] = 0;
	return 0;
}

static int clamps(pid_t pid, unsigned int min, unsigned int max)
{
	struct attr a;

	if (get_attr(pid, &a))
		return -1;
	a.flags = KEEP_ALL | CLAMPS;
	a.min = min;
	a.max = max;
	return set_attr(pid, &a);
}

static void cleanup(void)
{
	char value[32];
	unsigned int i;

	for (i = 0; i < 4; i++) {
		if (workers[i] <= 0)
			continue;
		kill(workers[i], SIGKILL);
		waitpid(workers[i], NULL, 0);
	}
	if (sysctl_changed) {
		snprintf(value, sizeof(value), "%d", saved_max);
		write_value("/proc/sys/kernel", "sched_util_clamp_max", value);
		snprintf(value, sizeof(value), "%d", saved_min);
		write_value("/proc/sys/kernel", "sched_util_clamp_min", value);
	}
	if (root[0])
		move_pid(root, getpid());
	if (child[0])
		rmdir(child);
	if (parent[0])
		rmdir(parent);
}

static void check(int ok, const char *what)
{
	checks++;
	printf("%s %u - %s", ok ? "ok" : "not ok", checks, what);
	if (!ok)
		printf(" (errno=%d: %s)", errno, strerror(errno));
	putchar('\n');
	if (!ok)
		exit(1);
}

static int effective(pid_t pid, unsigned int *min, unsigned int *max)
{
	char path[64], line[512];
	unsigned int found = 0;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/sched", pid ? pid : getpid());
	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "effective uclamp.min : %u", min) == 1)
			found |= 1;
		if (sscanf(line, "effective uclamp.max : %u", max) == 1)
			found |= 2;
	}
	fclose(f);
	return found == 3 ? 0 : -1;
}

static void abi_tests(void)
{
	struct attr a;
	struct {
		struct attr a;
		uint64_t tail;
	} large;
	unsigned char old[64];
	int ret;

	check(!clamps(0, 256, 768), "set explicit task clamps");
	check(!get_attr(0, &a) && a.min == 256 && a.max == 768,
	      "read requested task clamps");
	memset(old, 0xa5, sizeof(old));
	ret = syscall(__NR_sched_getattr, 0, old, 48, 0);
	check(!ret && *(uint32_t *)old == 48 && old[48] == 0xa5,
	      "48-byte getattr preserves the caller's tail");
	check(!get_attr(0, &a), "get current scheduling parameters");
	a.size = 48;
	a.flags = KEEP_ALL | CLAMPS;
	check(set_attr(0, &a) == -1 && errno == EINVAL,
	      "short setattr cannot silently drop clamp fields");
	check(clamps(0, 900, 800) == -1 && errno == EINVAL,
	      "reject inverted task limits");
	check(clamps(0, 0, 1025) == -1 && errno == EINVAL,
	      "reject task values above capacity scale");
	check(!get_attr(0, &a), "read clamps after invalid updates");
	a.flags = KEEP_ALL | CLAMP_MIN;
	a.min = 900;
	check(set_attr(0, &a) == -1 && errno == EINVAL,
	      "single minimum update respects existing maximum");
	a.flags = KEEP_ALL | CLAMP_MAX;
	a.max = 100;
	check(set_attr(0, &a) == -1 && errno == EINVAL,
	      "single maximum update respects existing minimum");
	check(!get_attr(0, &large.a), "prepare forward ABI test");
	large.a.flags = KEEP_ALL | CLAMPS;
	large.a.size = sizeof(large);
	large.tail = 0;
	check(!set_attr(0, &large.a), "accept a zero-filled future ABI tail");
	large.tail = 1;
	check(set_attr(0, &large.a) == -1 && errno == E2BIG,
	      "reject unknown nonzero ABI fields");
	check(!clamps(0, 0, 1024), "restore neutral task request");
}

static void fork_tests(void)
{
	struct attr a;
	pid_t pid;
	int status;

	check(!clamps(0, 123, 789), "prepare inherited clamps");
	pid = fork();
	if (pid)
		check(pid >= 0, "fork a task with clamp requests");
	if (!pid)
		_exit(get_attr(0, &a) || a.min != 123 || a.max != 789);
	waitpid(pid, &status, 0);
	check(WIFEXITED(status) && !WEXITSTATUS(status),
	      "child inherits explicit clamps");
	get_attr(0, &a);
	a.flags = RESET_ON_FORK;
	check(!set_attr(0, &a), "enable reset-on-fork");
	pid = fork();
	if (pid)
		check(pid >= 0, "fork with reset flag");
	if (!pid)
		_exit(get_attr(0, &a) || a.min || a.max != 1024);
	waitpid(pid, &status, 0);
	check(WIFEXITED(status) && !WEXITSTATUS(status),
	      "reset-on-fork clears explicit clamps");
	check(!clamps(0, 0, 1024), "restore parent after fork checks");
	get_attr(0, &a);
	a.flags = RESET_ON_FORK;
	check(!set_attr(0, &a), "clear explicit clamps in the RT test child");
	pid = fork();
	if (pid)
		check(pid >= 0, "fork RT policy test");
	if (!pid) {
		memset(&a, 0, sizeof(a));
		a.size = sizeof(a);
		a.policy = SCHED_FIFO;
		a.priority = 1;
		if (set_attr(0, &a) || get_attr(0, &a) ||
		    (a.min != 0 && a.min != 1024) || a.max != 1024)
			_exit(1);
		a.flags = RESET_ON_FORK;
		if (set_attr(0, &a))
			_exit(2);
		pid = fork();
		if (pid < 0)
			_exit(3);
		if (!pid)
			_exit(get_attr(0, &a) || a.policy != SCHED_OTHER ||
			      a.min || a.max != 1024);
		waitpid(pid, &status, 0);
		_exit(!WIFEXITED(status) || WEXITSTATUS(status));
	}
	waitpid(pid, &status, 0);
	check(WIFEXITED(status) && !WEXITSTATUS(status),
	      "RT defaults and RT reset-on-fork follow class changes");
	check(!clamps(0, 0, 1024), "restore parent after RT check");
}

static void permission_tests(void)
{
	struct attr a;
	pid_t parent_pid = getpid(), pid = fork();
	int status;

	if (pid)
		check(pid >= 0, "fork unprivileged caller");
	if (!pid) {
		if (setuid(65534) || clamps(0, 100, 900))
			_exit(1);
		get_attr(0, &a);
		a.flags = KEEP_ALL | CLAMPS;
		_exit(set_attr(parent_pid, &a) != -1 || errno != EPERM);
	}
	waitpid(pid, &status, 0);
	check(WIFEXITED(status) && !WEXITSTATUS(status),
	      "unprivileged self updates cannot change another user's task");
}

static void group_tests(void)
{
	unsigned int min, max;
	char value[128];

	check(!mkdir(parent, 0700), "create parent CPU group");
	check(!write_value(parent, "cpu.uclamp.min", "40"),
	      "set parent minimum");
	check(!write_value(parent, "cpu.uclamp.max", "80"),
	      "set parent maximum");
	check(!mkdir(child, 0700), "create child under restricted parent");
	check(!write_value(child, "cpu.uclamp.min", "60"),
	      "request child minimum above parent's allowance");
	check(!write_value(child, "cpu.uclamp.max", "90"),
	      "request child maximum above parent's allowance");
	check(!move_pid(child, getpid()), "attach current task to child");
	check(!effective(0, &min, &max), "read effective task clamps");
	check(min == 410 && max == 819,
	      "4.19 hierarchy restricts both child clamps to parent");
	check(!write_value(parent, "cpu.uclamp.min", "70"),
	      "increase parent minimum allowance");
	check(!effective(0, &min, &max) && min == 614 && max == 819,
	      "parent change updates already attached child task");
	check(!clamps(0, 900, 1000), "request task clamps above group cap");
	check(!effective(0, &min, &max) && min == 819 && max == 819,
	      "group maximum caps both task clamp requests");
	check(!clamps(0, 0, 1024), "restore task request in child group");
	check(!write_value(child, "cpu.uclamp.latency_sensitive", "1"),
	      "enable Android latency-sensitive attribute");
	check(!read_value(child, "cpu.uclamp.latency_sensitive",
			  value, sizeof(value)) && atoi(value) == 1,
	      "read Android latency-sensitive attribute");
	check(write_value(child, "cpu.uclamp.latency_sensitive", "2") < 0 &&
	      errno == EINVAL, "reject invalid latency flag");
	check(write_value(child, "cpu.uclamp.min", "-1") < 0 &&
	      errno == ERANGE, "reject negative group clamp");
	check(write_value(child, "cpu.uclamp.max", "100.01") < 0 &&
	      errno == ERANGE, "reject group clamp above 100 percent");
	check(!write_value(child, "cpu.uclamp.min", "12.34"),
	      "accept fractional group clamp");
	check(!read_value(child, "cpu.uclamp.min", value, sizeof(value)) &&
	      !strcmp(value, "12.34\n"), "preserve fractional readback");
	check(!move_pid(root, getpid()), "return current task to root group");
	check(!effective(0, &min, &max) && !min && max == 1024,
	      "group migration removes old effective restriction");
}

static void rt_group_tests(void)
{
	char value[32];
	int grouped, mode, status;
	pid_t pid;

	grouped = !read_value(child, "cpu.rt_runtime_us", value,
			     sizeof(value));
	check(grouped ? !strtol(value, NULL, 10) : errno == ENOENT,
	      "RT group fixture has zero budget or shares global runtime");
	for (mode = 0; mode < 2; mode++) {
		pid = fork();
		if (pid)
			check(pid >= 0, "fork RT cgroup test");
		if (!pid) {
			struct attr a = {
				.size = sizeof(a),
				.policy = SCHED_FIFO,
				.flags = CLAMPS,
				.priority = 1,
				.max = 1024,
			};
			unsigned int min, max;
			int ret, saved;

			if (mode ? set_attr(0, &a) : move_pid(child, getpid()))
				_exit(1);
			ret = mode ? move_pid(child, getpid()) : set_attr(0, &a);
			saved = errno;
			if (grouped) {
				printf("# Zero RT budget: %s returned errno=%d\n",
				       mode ? "migration" : "promotion", saved);
				_exit(ret != -1 ||
				      saved != (mode ? EINVAL : EPERM));
			}
			if (ret || get_attr(0, &a) || a.policy != SCHED_FIFO)
				_exit(2);
			if (effective(0, &min, &max) || min != 126 || max != 819)
				_exit(3);
			_exit(0);
		}
		check(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
		      !WEXITSTATUS(status), grouped ?
		      "zero RT budget rejects promotion and migration" :
		      "RT promotion and migration preserve effective group clamps");
	}
}

static void system_tests(void)
{
	unsigned int min, max;
	char value[32];

	if (!getenv("UCLAMP_TEST_ISOLATED")) {
		puts("# Skipping system-wide limits outside an isolated test");
		return;
	}
	check(!read_value("/proc/sys/kernel", "sched_util_clamp_min",
			  value, sizeof(value)), "read system minimum limit");
	saved_min = atoi(value);
	check(!read_value("/proc/sys/kernel", "sched_util_clamp_max",
			  value, sizeof(value)), "read system maximum limit");
	saved_max = atoi(value);
	check(saved_min == 1024 && saved_max == 1024,
	      "isolated test starts with neutral system limits");
	sysctl_changed = 1;
	check(!write_value("/proc/sys/kernel", "sched_util_clamp_min", "512"),
	      "lower system minimum allowance");
	check(!write_value("/proc/sys/kernel", "sched_util_clamp_max", "512"),
	      "lower system maximum allowance");
	check(!effective(0, &min, &max) && !min && max == 512,
	      "system clamp updates the running root-group task");
	check(write_value("/proc/sys/kernel", "sched_util_clamp_max", "511")
	      < 0 && errno == EINVAL, "reject inverted system limits");
	check(!write_value("/proc/sys/kernel", "sched_util_clamp_max", "1024"),
	      "restore system maximum");
	check(!write_value("/proc/sys/kernel", "sched_util_clamp_min", "1024"),
	      "restore system minimum allowance");
	sysctl_changed = 0;
}

static void stress_tests(void)
{
	const unsigned int edges[] = {0, 204, 205, 409, 410, 614,
				      615, 819, 820, 1024};
	cpu_set_t allowed, target;
	unsigned int i, j, ncpu = 0;
	int cpus[CPU_SETSIZE];
	char value[32];
	struct attr a;

	check(!sched_getaffinity(0, sizeof(allowed), &allowed),
	      "read available test CPUs");
	for (i = 0; i < CPU_SETSIZE; i++)
		if (CPU_ISSET(i, &allowed))
			cpus[ncpu++] = i;
	for (i = 0; i < 4; i++) {
		workers[i] = fork();
		if (workers[i])
			check(workers[i] >= 0, "fork runnable clamp worker");
		if (!workers[i]) {
			signal(SIGTERM, stop_worker);
			for (j = 0; !stopping; j++) {
				if (clamps(0, edges[j % 10], 1024))
					_exit(1);
				sched_yield();
				usleep(100);
			}
			_exit(0);
		}
	}
	for (j = 0; j < 300; j++) {
		snprintf(value, sizeof(value), "%u", j % 101);
		if (write_value(parent, "cpu.uclamp.min", value))
			check(0, "concurrent group clamp update");
		for (i = 0; i < 4; i++) {
			CPU_ZERO(&target);
			CPU_SET(cpus[(j + i) % ncpu], &target);
			if (sched_setaffinity(workers[i], sizeof(target), &target) ||
			    move_pid(j & 1 ? child : parent, workers[i]) ||
			    get_attr(workers[i], &a) || a.min > a.max ||
			    a.max > 1024) {
				check(0, "concurrent migration and clamp accounting");
			}
		}
	}
	for (i = 0; i < 4; i++) {
		int status;

		kill(workers[i], SIGTERM);
		waitpid(workers[i], &status, 0);
		workers[i] = 0;
		check(WIFEXITED(status) && !WEXITSTATUS(status),
		      "worker completes without clamp failure");
	}
}

int main(int argc, char **argv)
{
	struct statfs st;
	struct attr a;
	int ret;

	setbuf(stdout, NULL);
	puts("TAP version 13");
	if (argc != 2 || geteuid()) {
		puts("# Usage: uclamp <mounted cgroup-v1 CPU controller>");
		return 4;
	}
	check(sizeof(a) == 56, "sched_attr ABI size is 56 bytes");
	check(!statfs(argv[1], &st) && st.f_type == CGROUP_MAGIC,
	      "test root is a cgroup v1 mount");
	snprintf(root, sizeof(root), "%s", argv[1]);
	snprintf(parent, sizeof(parent), "%s/uclamp-test-%d", root, getpid());
	snprintf(child, sizeof(child), "%s/child", parent);
	atexit(cleanup);
	check(!get_attr(0, &a), "get scheduling attributes");
	a.flags = KEEP_ALL | CLAMPS;
	a.min = 0;
	a.max = 1024;
	ret = set_attr(0, &a);
	if (ret && errno == EOPNOTSUPP) {
		char value[32];

		check(!mkdir(parent, 0700), "create group without uclamp");
		check(read_value(parent, "cpu.uclamp.min", value, sizeof(value))
		      < 0 && errno == ENOENT, "disabled clamp files are absent");
		get_attr(0, &a);
		a.flags = 0;
		a.size = 48;
		check(!set_attr(0, &a), "legacy scheduler ABI still works");
		puts("# Utilization clamping is disabled in this build");
		printf("1..%u\n", checks);
		return 0;
	}
	check(!ret, "activate utilization clamping");
	abi_tests();
	fork_tests();
	permission_tests();
	group_tests();
	rt_group_tests();
	system_tests();
	stress_tests();
	printf("1..%u\n", checks);
	return 0;
}
