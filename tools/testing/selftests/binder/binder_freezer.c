// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../../../include/uapi/linux/android/binder.h"

#define PAYLOAD 0x72981631U
#define MAP_SIZE (1UL << 20)
static unsigned int passed, failed;
static char device[256], group[256];

static void fatal(const char *what)
{
	perror(what);
	exit(2);
}

static void check(bool ok, const char *name)
{
	printf("%s %u - %s", ok ? "ok" : "not ok",
	       passed + failed + 1, name);
	if (!ok)
		printf(" (errno=%d: %s)", errno, strerror(errno));
	putchar('\n');
	if (ok)
		passed++;
	else
		failed++;
}

static int write_command(int fd, uint32_t command,
			 const void *data, size_t size)
{
	unsigned char buffer[256];
	struct binder_write_read bwr = { 0 };

	if (size + sizeof(command) > sizeof(buffer))
		abort();
	memcpy(buffer, &command, sizeof(command));
	if (size)
		memcpy(buffer + sizeof(command), data, size);
	bwr.write_size = sizeof(command) + size;
	bwr.write_buffer = (uintptr_t)buffer;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr))
		return -1;
	return bwr.write_consumed == bwr.write_size ? 0 : -1;
}

static int read_command(int fd, uint32_t wanted,
			struct binder_transaction_data *transaction)
{
	unsigned char buffer[4096];
	unsigned int tries;

	for (tries = 0; tries < 5000; tries++) {
		struct binder_write_read bwr = {
			.read_size = sizeof(buffer),
			.read_buffer = (uintptr_t)buffer,
		};
		size_t offset = 0;

		if (ioctl(fd, BINDER_WRITE_READ, &bwr)) {
			if (errno != EAGAIN && errno != EINTR)
				return -1;
			usleep(1000);
			continue;
		}
		while (offset + sizeof(uint32_t) <= bwr.read_consumed) {
			uint32_t cmd;
			size_t size;

			memcpy(&cmd, buffer + offset, sizeof(cmd));
			offset += sizeof(cmd);
			size = _IOC_SIZE(cmd);
			if (offset + size > bwr.read_consumed)
				return -1;
			if (cmd == wanted) {
				if (transaction) {
					if (size != sizeof(*transaction))
						return -1;
					memcpy(transaction, buffer + offset,
					       size);
				}
				return 0;
			}
			if (cmd != BR_NOOP && cmd != BR_TRANSACTION_COMPLETE) {
				fprintf(stderr,
					"Unexpected Binder command %#x\n", cmd);
				return -1;
			}
			offset += size;
		}
	}
	errno = ETIMEDOUT;
	return -1;
}

static int send_transaction(int fd, bool reply, bool oneway)
{
	uint32_t payload = PAYLOAD;
	struct binder_transaction_data t = {
		.target.handle = 0,
		.code = 1,
		.flags = oneway ? TF_ONE_WAY : 0,
		.data_size = sizeof(payload),
		.data.ptr.buffer = (uintptr_t)&payload,
	};

	return write_command(fd, reply ? BC_REPLY : BC_TRANSACTION,
			     &t, sizeof(t));
}

static int free_buffer(int fd, struct binder_transaction_data *t)
{
	return write_command(fd, BC_FREE_BUFFER, &t->data.ptr.buffer,
			     sizeof(t->data.ptr.buffer));
}

static bool payload_ok(struct binder_transaction_data *t)
{
	uint32_t payload;

	if (t->data_size != sizeof(payload))
		return false;
	memcpy(&payload, (void *)(uintptr_t)t->data.ptr.buffer,
	       sizeof(payload));
	return payload == PAYLOAD;
}

static int binder_open(void **mapping)
{
	int fd = open(device, O_RDWR | O_CLOEXEC | O_NONBLOCK);

	if (fd < 0)
		fatal("open binder");
	*mapping = mmap(NULL, MAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
	if (*mapping == MAP_FAILED)
		fatal("mmap binder");
	return fd;
}

static void server(int socket)
{
	struct binder_transaction_data pending;
	void *mapping;
	int fd = binder_open(&mapping);
	char command, result;

	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, 0) ||
	    write_command(fd, BC_ENTER_LOOPER, NULL, 0))
		fatal("register context manager");
	if (write(socket, "r", 1) != 1)
		fatal("ready notification");
	while (read(socket, &command, 1) == 1) {
		result = 0;
		switch (command) {
		case 'R':
		case 'A':
			if (read_command(fd, BR_TRANSACTION, &pending) ||
			    !payload_ok(&pending))
				result = 1;
			if (!result && command == 'A' &&
			    (!(pending.flags & TF_ONE_WAY) ||
			     free_buffer(fd, &pending)))
				result = 1;
			break;
		case 'S':
			if (send_transaction(fd, true, false) ||
			    free_buffer(fd, &pending))
				result = 1;
			break;
		default:
			result = 1;
		}
		if (write(socket, &result, 1) != 1)
			fatal("response notification");
	}
	_exit(2);
}

static bool ask(int socket, char command)
{
	char result;

	return write(socket, &command, 1) == 1 &&
		read(socket, &result, 1) == 1 && result == 0;
}

static int freeze_binder(int fd, pid_t pid, bool enable, unsigned int ms)
{
	struct binder_freeze_info info = {
		.pid = pid, .enable = enable, .timeout_ms = ms,
	};

	return ioctl(fd, BINDER_FREEZE, &info);
}

static int frozen_info(int fd, pid_t pid,
		       struct binder_frozen_status_info *info)
{
	memset(info, 0, sizeof(*info));
	info->pid = pid;
	return ioctl(fd, BINDER_GET_FROZEN_INFO, info);
}

static int cg_write(const char *file, const char *value)
{
	char path[512];
	int fd, ret;

	snprintf(path, sizeof(path), "%s/%s", group, file);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	ret = write(fd, value, strlen(value)) == (ssize_t)strlen(value)
		? 0 : -1;
	close(fd);
	return ret;
}

static bool cg_frozen(bool frozen)
{
	char path[512], data[256];
	unsigned int tries;

	snprintf(path, sizeof(path), "%s/cgroup.events", group);
	for (tries = 0; tries < 5000; tries++) {
		int fd = open(path, O_RDONLY);
		ssize_t n;

		if (fd < 0)
			return false;
		n = read(fd, data, sizeof(data) - 1);
		close(fd);
		if (n <= 0)
			return false;
		data[n] = 0;
		if (strstr(data, frozen ? "frozen 1" : "frozen 0"))
			return true;
		usleep(1000);
	}
	return false;
}

static int unmount_binder(const char *path)
{
	unsigned int tries;

	/* Binder releases process references through deferred work. */
	for (tries = 0; tries < 5000; tries++) {
		if (!umount(path))
			return 0;
		if (errno != EBUSY)
			return -1;
		usleep(1000);
	}
	return -1;
}

int main(int argc, char **argv)
{
	char mountpoint[] = "/tmp/binder-freezer-XXXXXX";
	char pid_string[32], byte;
	const char *cgroot = argc > 1 ? argv[1] : "/cg2";
	struct binder_frozen_status_info info;
	struct binder_transaction_data reply = { 0 };
	int sockets[2], fd, status;
	pid_t child;
	void *mapping;

	setvbuf(stdout, NULL, _IONBF, 0);
	puts("TAP version 13");
	if (geteuid() || !mkdtemp(mountpoint)) {
		puts("1..0 # SKIP requires root and a writable /tmp");
		return 4;
	}
	if (mount("binder", mountpoint, "binder", 0, NULL)) {
		rmdir(mountpoint);
		puts("1..0 # SKIP requires BinderFS");
		return 4;
	}
	alarm(120);
	snprintf(device, sizeof(device), "%s/binder", mountpoint);
	snprintf(group, sizeof(group), "%s/binder-freezer-%d", cgroot,
		 getpid());
	if (mkdir(group, 0700) ||
	    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets))
		fatal("test setup");
	child = fork();
	if (child < 0)
		fatal("fork");
	if (!child) {
		close(sockets[0]);
		server(sockets[1]);
	}
	close(sockets[1]);
	if (read(sockets[0], &byte, 1) != 1)
		fatal("wait for server");
	fd = binder_open(&mapping);
	snprintf(pid_string, sizeof(pid_string), "%d", child);
	check(!cg_write("cgroup.procs", pid_string), "move server into cgroup");
	check(!frozen_info(fd, child, &info) &&
	      !info.sync_recv && !info.async_recv, "query idle Binder process");
	check(!send_transaction(fd, false, false), "send synchronous call");
	check(ask(sockets[0], 'R'), "server receives call and holds reply");
	check(!frozen_info(fd, child, &info) && (info.sync_recv & 2),
	      "incoming transaction reported as pending");
	check(!frozen_info(fd, getpid(), &info) && (info.sync_recv & 2),
	      "outgoing transaction reported as pending");
	errno = 0;
	check(freeze_binder(fd, child, true, 10) == -1 && errno == EAGAIN,
	      "freeze refuses outstanding incoming transaction");
	errno = 0;
	check(freeze_binder(fd, getpid(), true, 0) == -1 && errno == EAGAIN,
	      "freeze refuses outgoing call awaiting reply");
	check(ask(sockets[0], 'S'), "server sends reply after failed freeze");
	check(!read_command(fd, BR_REPLY, &reply) && payload_ok(&reply),
	      "caller receives intact synchronous reply");
	check(!free_buffer(fd, &reply), "release synchronous reply buffer");
	check(!frozen_info(fd, child, &info) && !(info.sync_recv & 2),
	      "completed call clears pending state");
	check(!freeze_binder(fd, child, true, 0), "freeze idle Binder process");
	check(!cg_write("cgroup.freeze", "1") && cg_frozen(true),
	      "freeze server tasks after Binder quiesces");
	check(!send_transaction(fd, false, false) &&
	      !read_command(fd, BR_FROZEN_REPLY, NULL),
	      "sync call to frozen server returns BR_FROZEN_REPLY");
	check(!send_transaction(fd, false, true) &&
	      !send_transaction(fd, false, true),
	      "queue two one-way calls to frozen server");
	check(!frozen_info(fd, child, &info) &&
	      (info.sync_recv & 1) && info.async_recv,
	      "frozen status records sync and async traffic");
	check(!freeze_binder(fd, child, false, 0) &&
	      !cg_write("cgroup.freeze", "0") && cg_frozen(false),
	      "thaw Binder and server tasks");
	check(ask(sockets[0], 'A') && ask(sockets[0], 'A'),
	      "both queued one-way payloads survive freeze and thaw");
	check(!frozen_info(fd, child, &info) &&
	      !info.sync_recv && !info.async_recv,
	      "thaw resets traffic flags and draining clears pending count");
	check(!freeze_binder(fd, child, true, 0) &&
	      !cg_write("cgroup.freeze", "1") && cg_frozen(true),
	      "server can be frozen again after queued work drains");
	check(!send_transaction(fd, false, true) &&
	      !send_transaction(fd, false, true),
	      "queue work before terminating frozen server");
	kill(child, SIGKILL);
	check(waitpid(child, &status, 0) == child &&
	      WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
	      "SIGKILL terminates frozen server with queued work");
	check(!cg_write("cgroup.freeze", "0") && !rmdir(group),
	      "remove cgroup after frozen process exit");
	close(sockets[0]);
	munmap(mapping, MAP_SIZE);
	close(fd);
	check(!unmount_binder(mountpoint) && !rmdir(mountpoint),
	      "remove private BinderFS instance");
	printf("1..%u\n# %u passed, %u failed\n",
	       passed + failed, passed, failed);
	return failed ? 1 : 0;
}
