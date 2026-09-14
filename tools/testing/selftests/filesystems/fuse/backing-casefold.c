// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <linux/android_fuse.h>
#include <linux/bpf.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <linux/fuse.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned int tests, failures;
static const char *variant;

static void check(bool ok, const char *name)
{
	int error = errno;

	printf("%s %u - %s: %s", ok ? "ok" : "not ok", ++tests,
	       variant, name);
	if (!ok) {
		printf(" (errno=%d: %s)", error, strerror(error));
		failures++;
	}
	putchar('\n');
}

static int load_filter(void)
{
	struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K,
		  .dst_reg = BPF_REG_0, .imm = FUSE_BPF_BACKING },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	struct rlimit limit = { RLIM_INFINITY, RLIM_INFINITY };
	char log[8192] = { };
	union bpf_attr attr = { };
	unsigned int type;
	FILE *file;
	int fd;

	file = fopen("/sys/fs/fuse/bpf_prog_type_fuse", "r");
	if (!file)
		return -1;
	if (fscanf(file, "%u", &type) != 1) {
		fclose(file);
		errno = EINVAL;
		return -1;
	}
	fclose(file);
	if (setrlimit(RLIMIT_MEMLOCK, &limit))
		return -1;
	attr.prog_type = type;
	attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
	attr.insns = (uintptr_t)insns;
	attr.license = (uintptr_t)"GPL";
	attr.log_buf = (uintptr_t)log;
	attr.log_size = sizeof(log);
	attr.log_level = 1;
	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (fd < 0)
		fprintf(stderr, "BPF load: %s\n%s\n",
			strerror(errno), log);
	return fd;
}

/* Mutations must use the backing path; only INIT is serviced. */
static void daemon_loop(int fd)
{
	union {
		struct fuse_in_header header;
		char bytes[65536];
	} request;
	struct {
		struct fuse_out_header header;
		struct fuse_init_out init;
	} reply;
	ssize_t size;

	for (;;) {
		size = read(fd, &request, sizeof(request));
		if (size < 0 && errno == EINTR)
			continue;
		if (size < (ssize_t)sizeof(request.header))
			break;
		if (request.header.opcode == FUSE_FORGET ||
		    request.header.opcode == FUSE_BATCH_FORGET)
			continue;
		memset(&reply, 0, sizeof(reply));
		reply.header.unique = request.header.unique;
		reply.header.len = sizeof(reply.header);
		if (request.header.opcode == FUSE_INIT) {
			reply.init.major = FUSE_KERNEL_VERSION;
			reply.init.minor = FUSE_KERNEL_MINOR_VERSION;
			reply.init.max_write = 4096;
			reply.init.time_gran = 1;
			reply.header.len = sizeof(reply);
		} else {
			reply.header.error = -ENOSYS;
		}
		if (write(fd, &reply, reply.header.len) < 0)
			break;
	}
	_exit(0);
}

static int encrypt_dir(int fd)
{
	struct fscrypt_add_key_arg *key;
	struct fscrypt_policy_v2 policy = {
		.version = FSCRYPT_POLICY_V2,
		.contents_encryption_mode = FSCRYPT_MODE_AES_256_XTS,
		.filenames_encryption_mode = FSCRYPT_MODE_AES_256_CTS,
	};
	int ret;

	key = calloc(1, sizeof(*key) + 64);
	if (!key)
		return -1;
	key->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
	key->raw_size = 64;
	/* Public fixed key for the disposable test directory. */
	memset(key->raw, 0x42, 64);
	ret = ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, key);
	if (!ret) {
		memcpy(policy.master_key_identifier,
		       key->key_spec.u.identifier,
		       sizeof(policy.master_key_identifier));
		ret = ioctl(fd, FS_IOC_SET_ENCRYPTION_POLICY, &policy);
	}
	free(key);
	return ret;
}

static int create_file(int dir, const char *name, int flags)
{
	int fd = openat(dir, name, O_CREAT | O_RDWR | flags, 0600);
	int ret = -1;
	int error;

	if (fd >= 0)
		ret = write(fd, "casefold", 8) == 8 ? 0 : -1;
	error = errno;
	if (fd >= 0)
		close(fd);
	errno = error;
	return ret;
}

static bool read_file(int dir, const char *name)
{
	char buffer[8];
	int fd = openat(dir, name, O_RDONLY);
	bool ok = false;

	if (fd >= 0) {
		ok = read(fd, buffer, sizeof(buffer)) == sizeof(buffer);
		ok = ok &&
		     !memcmp(buffer, "casefold", sizeof(buffer));
		close(fd);
	}
	return ok;
}

static bool race_create(int upper, int lower, bool folded)
{
	int i;

	for (i = 0; i < 32; i++) {
		const char *lower_name = folded ? "RACE" : "race";
		int gate[2], status, ret, error;
		char byte;
		pid_t pid;

		if (pipe(gate))
			return false;
		pid = fork();
		if (!pid) {
			close(gate[1]);
			if (read(gate[0], &byte, 1) != 1)
				_exit(2);
			ret = create_file(lower, lower_name, O_EXCL);
			_exit(!ret ? 0 : errno == EEXIST ? 1 : 2);
		}
		if (pid < 0) {
			close(gate[0]);
			close(gate[1]);
			return false;
		}
		close(gate[0]);
		ret = write(gate[1], "x", 1);
		close(gate[1]);
		if (ret == 1)
			ret = create_file(upper, "race", O_EXCL);
		error = errno;
		if (waitpid(pid, &status, 0) != pid ||
		    !WIFEXITED(status))
			return false;
		status = WEXITSTATUS(status);
		if ((!ret && status != 1) ||
		    (ret && (error != EEXIST || status != 0))) {
			errno = error;
			return false;
		}
		if (unlinkat(lower, lower_name, 0))
			return false;
	}
	return true;
}

static void exercise(int upper, int lower, bool folded)
{
	struct stat st;
	char link[32];
	int fd, ret;

	check(!mkdirat(upper, "package", 0700), "mkdir new package");
	fd = openat(upper, "package", O_RDONLY | O_DIRECTORY);
	check(fd >= 0, "reopen created directory");
	if (fd >= 0) {
		check(!mkdirat(fd, "temp", 0700), "mkdir nested temp");
		close(fd);
	}
	check(!create_file(upper, "package/temp/main.obb.staged",
			   O_EXCL),
	      "create OBB staging file");
	check(!renameat(upper, "package/temp/main.obb.staged",
			upper, "package/main.obb"),
			      "finalize OBB by rename");
	check(read_file(upper, "package/main.obb"),
	      "read finalized OBB");

	check(!create_file(upper, "file", O_EXCL),
	      "create regular file");
	check(read_file(upper, "file"), "read after close and reopen");
	ret = create_file(upper, "file", O_EXCL);
	check(ret == -1 && errno == EEXIST,
	      "exclusive create collision");
	ret = fstatat(upper, "missing", &st, 0);
	check(ret == -1 && errno == ENOENT, "negative lookup");
	check(!mkdirat(upper, "missing", 0700),
	      "mkdir after negative lookup");
	ret = fstatat(upper, "external", &st, 0);
	check(ret == -1 && errno == ENOENT, "cache lower miss");
	check(!create_file(lower, "external", O_EXCL) &&
	      read_file(upper, "external"),
	      "observe later lower creation");
	check(!mknodat(upper, "fifo", S_IFIFO | 0600, 0), "mknod FIFO");
	check(!symlinkat("file", upper, "symlink"), "create symlink");
	ret = readlinkat(upper, "symlink", link, sizeof(link));
	check(ret == 4 && !memcmp(link, "file", 4),
	      "read created symlink");
	check(!linkat(upper, "file", upper, "hardlink", 0),
	      "create hardlink");
	check(read_file(upper, "hardlink"), "read hardlink");
	check(!renameat(upper, "file", upper, "moved"),
	      "rename to new name");
	check(read_file(upper, "moved"), "read renamed file");
	check(!unlinkat(upper, "moved", 0), "unlink created file");
	check(!unlinkat(upper, "missing", AT_REMOVEDIR),
	      "rmdir created dir");
	check(!create_file(upper, "Mixed", O_EXCL),
	      "create mixed-case name");
	if (folded) {
		check(read_file(upper, "mIXED"),
		      "case-insensitive reopen");
		ret = create_file(upper, "mixed", O_EXCL);
		check(ret == -1 && errno == EEXIST,
		      "casefold collision");
		check(!renameat(upper, "mIXED", upper, "Renamed"),
		      "case-insensitive rename source");
		check(!create_file(upper, "target", O_EXCL) &&
		      !renameat(upper, "rENAMED", upper, "TARGET"),
		      "case-insensitive rename replacement");
		check(read_file(upper, "target"),
		      "read rename replacement");
		check(!unlinkat(upper, "TARGET", 0),
		      "case-insensitive unlink");
		check(!mkdirat(upper, "Dir", 0700) &&
		      !unlinkat(upper, "dIR", AT_REMOVEDIR),
		      "case-insensitive rmdir");
		check(!create_file(upper, "\303\204pfel", O_EXCL) &&
		      read_file(upper, "\303\244PFEL"),
		      "Unicode casefold reopen");
	}
	check(race_create(upper, lower, folded),
	      "32 lower/upper create races");
}

static int remove_entry(const char *path, const struct stat *st,
			int type, struct FTW *info)
{
	(void)st;
	(void)type;
	(void)info;
	return remove(path);
}

static void run_variant(const char *base, int prog, int mode)
{
	char lower[PATH_MAX], upper[] = "/tmp/fuse-casefold.XXXXXX";
	char options[256];
	int lower_fd = -1, fuse_fd = -1, upper_fd = -1;
	int flags = FS_CASEFOLD_FL;
	bool mounted = false;
	pid_t daemon = -1;

	variant = mode == 0 ? "ordinary" : mode == 1 ? "casefold" :
		  "encrypted casefold";
	if (snprintf(lower, sizeof(lower), "%s/fuse-test.XXXXXX",
		     base) >=
	    (int)sizeof(lower)) {
		errno = ENAMETOOLONG;
		check(false, "scratch path");
		return;
	}
	if (!mkdtemp(lower)) {
		check(false, "create scratch directory");
		return;
	}
	if (!mkdtemp(upper)) {
		check(false, "create mountpoint");
		goto out_lower;
	}
	lower_fd = open(lower, O_RDONLY | O_DIRECTORY);
	if (lower_fd < 0 ||
	    (mode && ioctl(lower_fd, FS_IOC_SETFLAGS, &flags)) ||
	    (mode == 2 && encrypt_dir(lower_fd))) {
		check(false, "configure backing directory");
		goto out;
	}
	fuse_fd = open("/dev/fuse", O_RDWR);
	if (fuse_fd < 0) {
		check(false, "open FUSE device");
		goto out;
	}
	snprintf(options, sizeof(options),
		 "fd=%d,rootmode=40000,user_id=0,group_id=0,"
		 "root_dir=%d,root_bpf=%d", fuse_fd, lower_fd, prog);
	if (mount("fuse", upper, "fuse", MS_NOSUID | MS_NODEV,
		  options)) {
		check(false, "mount FUSE-BPF");
		goto out;
	}
	mounted = true;
	daemon = fork();
	if (!daemon)
		daemon_loop(fuse_fd);
	if (daemon < 0) {
		check(false, "start handshake daemon");
		goto out;
	}
	upper_fd = open(upper, O_RDONLY | O_DIRECTORY);
	if (upper_fd < 0) {
		check(false, "open FUSE-BPF root");
		goto out;
	}
	exercise(upper_fd, lower_fd, mode != 0);
 out:
	if (upper_fd >= 0)
		close(upper_fd);
	if (mounted)
		umount2(upper, MNT_DETACH);
	if (daemon > 0) {
		kill(daemon, SIGTERM);
		waitpid(daemon, NULL, 0);
	}
	if (fuse_fd >= 0)
		close(fuse_fd);
	if (lower_fd >= 0)
		close(lower_fd);
	rmdir(upper);
 out_lower:
	if (nftw(lower, remove_entry, 16, FTW_DEPTH | FTW_PHYS))
		check(false, "remove scratch directory");
}

int main(int argc, char **argv)
{
	int prog, i;

	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(120);
	if (argc != 2 || geteuid()) {
		puts("1..0 # SKIP need root and a disposable test FS");
		return 4;
	}
	prog = load_filter();
	if (prog < 0) {
		perror("load FUSE-BPF filter");
		return 1;
	}
	puts("TAP version 13");
	for (i = 0; i < 3; i++)
		run_variant(argv[1], prog, i);
	close(prog);
	printf("1..%u\n# %u passed, %u failed\n", tests,
	       tests - failures, failures);
	return failures ? 1 : 0;
}
