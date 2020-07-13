// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Resolve kernel .BTF_ids symbols against an ELF object's BTF data.
 *
 * This backport deliberately keeps the resolver self-contained.  The
 * Exynos9810 4.9 tools tree predates libbpf's userspace BTF parser, while
 * resolve_btfids has to be available before the final kernel link.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define BTF_MAGIC 0xeb9f
#define BTF_VERSION 1
#define BTF_IDS_SECTION ".BTF_ids"
#define BTF_SECTION ".BTF"
#define BTF_ID_PREFIX "__BTF_ID__"

#define BTF_KIND_UNKN 0
#define BTF_KIND_INT 1
#define BTF_KIND_PTR 2
#define BTF_KIND_ARRAY 3
#define BTF_KIND_STRUCT 4
#define BTF_KIND_UNION 5
#define BTF_KIND_ENUM 6
#define BTF_KIND_FWD 7
#define BTF_KIND_TYPEDEF 8
#define BTF_KIND_VOLATILE 9
#define BTF_KIND_CONST 10
#define BTF_KIND_RESTRICT 11
#define BTF_KIND_FUNC 12
#define BTF_KIND_FUNC_PROTO 13
#define BTF_KIND_VAR 14
#define BTF_KIND_DATASEC 15
#define BTF_KIND_FLOAT 16
#define BTF_KIND_DECL_TAG 17
#define BTF_KIND_TYPE_TAG 18
#define BTF_KIND_ENUM64 19

struct mapped_file {
	const char *path;
	unsigned char *data;
	size_t size;
	int fd;
	bool writable;
};

struct elf_view {
	struct mapped_file file;
	bool is_64;
	bool is_be;
	uint16_t type;
	uint64_t shoff;
	uint16_t shentsize;
	uint32_t shnum;
	uint32_t shstrndx;
};

struct elf_section {
	uint32_t name;
	uint32_t type;
	uint64_t flags;
	uint64_t addr;
	uint64_t offset;
	uint64_t size;
	uint32_t link;
	uint64_t entsize;
};

struct btf_header {
	uint16_t magic;
	uint8_t version;
	uint8_t flags;
	uint32_t hdr_len;
	uint32_t type_off;
	uint32_t type_len;
	uint32_t str_off;
	uint32_t str_len;
};

struct btf_view {
	const unsigned char *data;
	size_t size;
	bool is_be;
	const unsigned char *types;
	size_t types_len;
	const char *strings;
	size_t strings_len;
};

struct btf_id_symbol {
	uint64_t offset;
	uint64_t size;
	char *name;
	bool is_set;
};

struct symbol_list {
	struct btf_id_symbol *items;
	size_t count;
	size_t capacity;
};

static int verbose;

static void usage(FILE *out, const char *prog)
{
	fprintf(out, "Usage: %s [-v] [-b BTF_FILE] ELF_FILE\n", prog);
}

static uint16_t bswap16(uint16_t v)
{
	return (uint16_t)((v << 8) | (v >> 8));
}

static uint32_t bswap32(uint32_t v)
{
	return __builtin_bswap32(v);
}

static uint64_t bswap64(uint64_t v)
{
	return __builtin_bswap64(v);
}

static uint16_t get_u16(const void *ptr, bool be)
{
	uint16_t v;

	memcpy(&v, ptr, sizeof(v));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return be ? bswap16(v) : v;
#else
	return be ? v : bswap16(v);
#endif
}

static uint32_t get_u32(const void *ptr, bool be)
{
	uint32_t v;

	memcpy(&v, ptr, sizeof(v));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return be ? bswap32(v) : v;
#else
	return be ? v : bswap32(v);
#endif
}

static uint64_t get_u64(const void *ptr, bool be)
{
	uint64_t v;

	memcpy(&v, ptr, sizeof(v));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return be ? bswap64(v) : v;
#else
	return be ? v : bswap64(v);
#endif
}

static void put_u32(void *ptr, uint32_t v, bool be)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	if (be)
		v = bswap32(v);
#else
	if (!be)
		v = bswap32(v);
#endif
	memcpy(ptr, &v, sizeof(v));
}

static int map_file(struct mapped_file *file, const char *path, bool writable)
{
	struct stat st;
	int prot = PROT_READ;

	memset(file, 0, sizeof(*file));
	file->fd = -1;
	file->path = path;
	file->writable = writable;
	file->fd = open(path, writable ? O_RDWR : O_RDONLY);
	if (file->fd < 0) {
		fprintf(stderr, "FAILED: open %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (fstat(file->fd, &st)) {
		fprintf(stderr, "FAILED: stat %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (st.st_size <= 0) {
		fprintf(stderr, "FAILED: %s is empty\n", path);
		return -1;
	}
	file->size = (size_t)st.st_size;
	if (writable)
		prot |= PROT_WRITE;
	file->data = mmap(NULL, file->size, prot, MAP_SHARED, file->fd, 0);
	if (file->data == MAP_FAILED) {
		file->data = NULL;
		fprintf(stderr, "FAILED: mmap %s: %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

static void unmap_file(struct mapped_file *file)
{
	if (file->data) {
		if (file->writable)
			msync(file->data, file->size, MS_SYNC);
		munmap(file->data, file->size);
	}
	if (file->fd >= 0)
		close(file->fd);
	memset(file, 0, sizeof(*file));
	file->fd = -1;
}

static bool range_ok(size_t size, uint64_t off, uint64_t len)
{
	return off <= size && len <= size - off;
}

static int elf_open(struct elf_view *elf, const char *path, bool writable)
{
	const unsigned char *e;

	memset(elf, 0, sizeof(*elf));
	if (map_file(&elf->file, path, writable))
		return -1;
	if (elf->file.size < EI_NIDENT) {
		fprintf(stderr, "FAILED: %s is not an ELF file\n", path);
		return -1;
	}
	e = elf->file.data;
	if (memcmp(e, ELFMAG, SELFMAG)) {
		fprintf(stderr, "FAILED: %s has invalid ELF magic\n", path);
		return -1;
	}
	if (e[EI_CLASS] != ELFCLASS32 && e[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "FAILED: unsupported ELF class in %s\n", path);
		return -1;
	}
	if (e[EI_DATA] != ELFDATA2LSB && e[EI_DATA] != ELFDATA2MSB) {
		fprintf(stderr, "FAILED: unsupported ELF byte order in %s\n", path);
		return -1;
	}
	elf->is_64 = e[EI_CLASS] == ELFCLASS64;
	elf->is_be = e[EI_DATA] == ELFDATA2MSB;
	if (elf->is_64) {
		const Elf64_Ehdr *h;

		if (elf->file.size < sizeof(*h))
			return -1;
		h = (const Elf64_Ehdr *)e;
		elf->type = get_u16(&h->e_type, elf->is_be);
		elf->shoff = get_u64(&h->e_shoff, elf->is_be);
		elf->shentsize = get_u16(&h->e_shentsize, elf->is_be);
		elf->shnum = get_u16(&h->e_shnum, elf->is_be);
		elf->shstrndx = get_u16(&h->e_shstrndx, elf->is_be);
	} else {
		const Elf32_Ehdr *h;

		if (elf->file.size < sizeof(*h))
			return -1;
		h = (const Elf32_Ehdr *)e;
		elf->type = get_u16(&h->e_type, elf->is_be);
		elf->shoff = get_u32(&h->e_shoff, elf->is_be);
		elf->shentsize = get_u16(&h->e_shentsize, elf->is_be);
		elf->shnum = get_u16(&h->e_shnum, elf->is_be);
		elf->shstrndx = get_u16(&h->e_shstrndx, elf->is_be);
	}
	if (!elf->shoff || !elf->shentsize || !elf->shnum ||
	    !range_ok(elf->file.size, elf->shoff,
		      (uint64_t)elf->shentsize * elf->shnum)) {
		fprintf(stderr, "FAILED: invalid ELF section table in %s\n", path);
		return -1;
	}
	if (elf->shstrndx >= elf->shnum) {
		fprintf(stderr, "FAILED: invalid ELF section-name index in %s\n", path);
		return -1;
	}
	return 0;
}

static void elf_close(struct elf_view *elf)
{
	unmap_file(&elf->file);
}

static int elf_section(const struct elf_view *elf, uint32_t index,
		       struct elf_section *sec)
{
	const unsigned char *p;

	if (index >= elf->shnum)
		return -1;
	p = elf->file.data + elf->shoff + (uint64_t)index * elf->shentsize;
	memset(sec, 0, sizeof(*sec));
	if (elf->is_64) {
		const Elf64_Shdr *s = (const Elf64_Shdr *)p;

		sec->name = get_u32(&s->sh_name, elf->is_be);
		sec->type = get_u32(&s->sh_type, elf->is_be);
		sec->flags = get_u64(&s->sh_flags, elf->is_be);
		sec->addr = get_u64(&s->sh_addr, elf->is_be);
		sec->offset = get_u64(&s->sh_offset, elf->is_be);
		sec->size = get_u64(&s->sh_size, elf->is_be);
		sec->link = get_u32(&s->sh_link, elf->is_be);
		sec->entsize = get_u64(&s->sh_entsize, elf->is_be);
	} else {
		const Elf32_Shdr *s = (const Elf32_Shdr *)p;

		sec->name = get_u32(&s->sh_name, elf->is_be);
		sec->type = get_u32(&s->sh_type, elf->is_be);
		sec->flags = get_u32(&s->sh_flags, elf->is_be);
		sec->addr = get_u32(&s->sh_addr, elf->is_be);
		sec->offset = get_u32(&s->sh_offset, elf->is_be);
		sec->size = get_u32(&s->sh_size, elf->is_be);
		sec->link = get_u32(&s->sh_link, elf->is_be);
		sec->entsize = get_u32(&s->sh_entsize, elf->is_be);
	}
	if (!range_ok(elf->file.size, sec->offset, sec->size))
		return -1;
	return 0;
}

static const char *elf_string(const struct elf_view *elf,
			      const struct elf_section *strtab,
			      uint32_t offset)
{
	const char *s;

	if (offset >= strtab->size)
		return NULL;
	s = (const char *)elf->file.data + strtab->offset + offset;
	if (!memchr(s, '\0', strtab->size - offset))
		return NULL;
	return s;
}

static int elf_find_sections(const struct elf_view *elf,
			     struct elf_section *btf,
			     struct elf_section *ids,
			     uint32_t *ids_index,
			     struct elf_section *symtab)
{
	struct elf_section shstr;
	uint32_t i;

	if (elf_section(elf, elf->shstrndx, &shstr))
		return -1;
	memset(btf, 0, sizeof(*btf));
	memset(ids, 0, sizeof(*ids));
	memset(symtab, 0, sizeof(*symtab));
	*ids_index = 0;
	for (i = 0; i < elf->shnum; i++) {
		struct elf_section sec;
		const char *name;

		if (elf_section(elf, i, &sec))
			return -1;
		name = elf_string(elf, &shstr, sec.name);
		if (!name)
			return -1;
		if (!strcmp(name, BTF_SECTION))
			*btf = sec;
		else if (!strcmp(name, BTF_IDS_SECTION)) {
			*ids = sec;
			*ids_index = i;
		} else if (sec.type == SHT_SYMTAB)
			*symtab = sec;
	}
	return 0;
}

static int btf_open_raw(struct btf_view *btf, const unsigned char *data,
			size_t size, bool be)
{
	struct btf_header h;
	uint64_t type_start, str_start;

	if (size < 24)
		return -1;
	h.magic = get_u16(data, be);
	h.version = data[2];
	h.flags = data[3];
	h.hdr_len = get_u32(data + 4, be);
	h.type_off = get_u32(data + 8, be);
	h.type_len = get_u32(data + 12, be);
	h.str_off = get_u32(data + 16, be);
	h.str_len = get_u32(data + 20, be);
	if (h.magic != BTF_MAGIC || h.version != BTF_VERSION || h.hdr_len < 24)
		return -1;
	type_start = (uint64_t)h.hdr_len + h.type_off;
	str_start = (uint64_t)h.hdr_len + h.str_off;
	if (!range_ok(size, type_start, h.type_len) ||
	    !range_ok(size, str_start, h.str_len) || !h.str_len)
		return -1;
	memset(btf, 0, sizeof(*btf));
	btf->data = data;
	btf->size = size;
	btf->is_be = be;
	btf->types = data + type_start;
	btf->types_len = h.type_len;
	btf->strings = (const char *)data + str_start;
	btf->strings_len = h.str_len;
	if (btf->strings[0] != '\0')
		return -1;
	return 0;
}

static const char *btf_string(const struct btf_view *btf, uint32_t off)
{
	const char *s;

	if (off >= btf->strings_len)
		return NULL;
	s = btf->strings + off;
	if (!memchr(s, '\0', btf->strings_len - off))
		return NULL;
	return s;
}

static int btf_record_size(uint32_t kind, uint32_t vlen, size_t *extra)
{
	uint64_t n = 0;

	switch (kind) {
	case BTF_KIND_UNKN:
	case BTF_KIND_PTR:
	case BTF_KIND_FWD:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_FUNC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_TYPE_TAG:
		break;
	case BTF_KIND_INT:
	case BTF_KIND_VAR:
	case BTF_KIND_DECL_TAG:
		n = 4;
		break;
	case BTF_KIND_ARRAY:
		n = 12;
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
	case BTF_KIND_ENUM64:
		n = (uint64_t)vlen * 12;
		break;
	case BTF_KIND_ENUM:
	case BTF_KIND_FUNC_PROTO:
		n = (uint64_t)vlen * 8;
		break;
	case BTF_KIND_DATASEC:
		n = (uint64_t)vlen * 12;
		break;
	default:
		return -1;
	}
	if (n > SIZE_MAX)
		return -1;
	*extra = (size_t)n;
	return 0;
}

static int btf_find_id(const struct btf_view *btf, uint32_t want_kind,
		       const char *want_name, uint32_t *result)
{
	size_t off = 0;
	uint32_t id = 1;

	while (off < btf->types_len) {
		const unsigned char *p;
		const char *name;
		uint32_t name_off, info, kind, vlen;
		size_t extra;

		if (btf->types_len - off < 12)
			return -1;
		p = btf->types + off;
		name_off = get_u32(p, btf->is_be);
		info = get_u32(p + 4, btf->is_be);
		kind = (info >> 24) & 0x1f;
		vlen = info & 0xffff;
		if (btf_record_size(kind, vlen, &extra) ||
		    extra > btf->types_len - off - 12)
			return -1;
		name = btf_string(btf, name_off);
		if (!name)
			return -1;
		if (kind == want_kind && !strcmp(name, want_name)) {
			*result = id;
			return 0;
		}
		off += 12 + extra;
		id++;
	}
	return -ENOENT;
}

static int symbols_add(struct symbol_list *list, uint64_t offset,
		       uint64_t size, const char *name, bool is_set)
{
	struct btf_id_symbol *item;

	if (list->count == list->capacity) {
		size_t cap = list->capacity ? list->capacity * 2 : 32;
		void *p = realloc(list->items, cap * sizeof(*list->items));

		if (!p)
			return -1;
		list->items = p;
		list->capacity = cap;
	}
	item = &list->items[list->count++];
	item->offset = offset;
	item->size = size;
	item->name = strdup(name);
	item->is_set = is_set;
	return item->name ? 0 : -1;
}

static void symbols_free(struct symbol_list *list)
{
	size_t i;

	for (i = 0; i < list->count; i++)
		free(list->items[i].name);
	free(list->items);
	memset(list, 0, sizeof(*list));
}

static int collect_symbols(const struct elf_view *elf,
			   const struct elf_section *ids,
			   uint32_t ids_index,
			   const struct elf_section *symtab,
			   struct symbol_list *list)
{
	struct elf_section strtab;
	uint64_t count, i;

	if (!symtab->entsize || symtab->link >= elf->shnum ||
	    elf_section(elf, symtab->link, &strtab))
		return -1;
	count = symtab->size / symtab->entsize;
	for (i = 0; i < count; i++) {
		const unsigned char *p = elf->file.data + symtab->offset +
					 (uint64_t)i * symtab->entsize;
		uint32_t name_off;
		uint16_t shndx;
		uint64_t value, size, off;
		const char *name;

		if (elf->is_64) {
			const Elf64_Sym *sym = (const Elf64_Sym *)p;

			name_off = get_u32(&sym->st_name, elf->is_be);
			shndx = get_u16(&sym->st_shndx, elf->is_be);
			value = get_u64(&sym->st_value, elf->is_be);
			size = get_u64(&sym->st_size, elf->is_be);
		} else {
			const Elf32_Sym *sym = (const Elf32_Sym *)p;

			name_off = get_u32(&sym->st_name, elf->is_be);
			shndx = get_u16(&sym->st_shndx, elf->is_be);
			value = get_u32(&sym->st_value, elf->is_be);
			size = get_u32(&sym->st_size, elf->is_be);
		}
		if (shndx != ids_index)
			continue;
		name = elf_string(elf, &strtab, name_off);
		if (!name || strncmp(name, BTF_ID_PREFIX,
				    sizeof(BTF_ID_PREFIX) - 1))
			continue;
		if (value < ids->addr)
			return -1;
		off = value - ids->addr;
		if (!range_ok(ids->size, off, 4))
			return -1;
		if (symbols_add(list, off, size, name,
				!strncmp(name + sizeof(BTF_ID_PREFIX) - 1,
					 "set__", 5)))
			return -1;
	}
	return 0;
}

static char *parse_id_name(const char *symbol, uint32_t *kind)
{
	const char *p = symbol + sizeof(BTF_ID_PREFIX) - 1;
	const char *sep, *tail;
	char kind_name[16];
	char *name;
	size_t len;

	sep = strstr(p, "__");
	if (!sep || sep == p || (size_t)(sep - p) >= sizeof(kind_name))
		return NULL;
	memcpy(kind_name, p, sep - p);
	kind_name[sep - p] = '\0';
	if (!strcmp(kind_name, "struct"))
		*kind = BTF_KIND_STRUCT;
	else if (!strcmp(kind_name, "union"))
		*kind = BTF_KIND_UNION;
	else if (!strcmp(kind_name, "typedef"))
		*kind = BTF_KIND_TYPEDEF;
	else if (!strcmp(kind_name, "func"))
		*kind = BTF_KIND_FUNC;
	else
		return NULL;
	p = sep + 2;
	tail = p + strlen(p);
	while (tail > p && isdigit((unsigned char)tail[-1]))
		tail--;
	if (tail == p || tail - p < 2 || tail[-1] != '_' || tail[-2] != '_')
		return NULL;
	len = (size_t)(tail - p - 2);
	if (!len)
		return NULL;
	name = malloc(len + 1);
	if (!name)
		return NULL;
	memcpy(name, p, len);
	name[len] = '\0';
	return name;
}

static int u32_compare(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a;
	uint32_t y = *(const uint32_t *)b;

	return (x > y) - (x < y);
}

static int resolve_symbols(struct elf_view *elf,
			   const struct elf_section *ids,
			   const struct btf_view *btf,
			   const struct symbol_list *list)
{
	unsigned char *data = elf->file.data + ids->offset;
	size_t i;

	for (i = 0; i < list->count; i++) {
		const struct btf_id_symbol *sym = &list->items[i];
		uint32_t kind, id;
		char *name;
		int err;

		if (sym->is_set)
			continue;
		name = parse_id_name(sym->name, &kind);
		if (!name) {
			fprintf(stderr, "FAILED: parse BTF ID symbol %s\n", sym->name);
			return -1;
		}
		err = btf_find_id(btf, kind, name, &id);
		if (err) {
			fprintf(stderr, "FAILED: BTF type %s for %s was not found\n",
				name, sym->name);
			free(name);
			return -1;
		}
		put_u32(data + sym->offset, id, elf->is_be);
		if (verbose)
			printf("%s -> %u\n", sym->name, id);
		free(name);
	}

	for (i = 0; i < list->count; i++) {
		const struct btf_id_symbol *sym = &list->items[i];
		uint32_t *values;
		uint64_t n, j;

		if (!sym->is_set)
			continue;
		if (sym->size < 4 || sym->size % 4 ||
		    !range_ok(ids->size, sym->offset, sym->size)) {
			fprintf(stderr, "FAILED: invalid BTF set %s size %" PRIu64 "\n",
				sym->name, sym->size);
			return -1;
		}
		n = sym->size / 4 - 1;
		if (n > UINT32_MAX)
			return -1;
		values = calloc(n ? n : 1, sizeof(*values));
		if (!values)
			return -1;
		for (j = 0; j < n; j++)
			values[j] = get_u32(data + sym->offset + 4 + j * 4,
					    elf->is_be);
		qsort(values, n, sizeof(*values), u32_compare);
		put_u32(data + sym->offset, (uint32_t)n, elf->is_be);
		for (j = 0; j < n; j++)
			put_u32(data + sym->offset + 4 + j * 4, values[j],
				elf->is_be);
		if (verbose)
			printf("%s -> set with %" PRIu64 " IDs\n", sym->name, n);
		free(values);
	}
	return 0;
}

static int get_btf_view(const char *path, const struct elf_view *target,
			struct mapped_file *external,
			struct btf_view *btf)
{
	if (!path) {
		struct elf_section btf_sec, ids, symtab;
		uint32_t ids_index;

		if (elf_find_sections(target, &btf_sec, &ids, &ids_index,
				      &symtab) || !btf_sec.size) {
			fprintf(stderr, "FAILED: %s has no .BTF section\n",
				target->file.path);
			return -1;
		}
		return btf_open_raw(btf, target->file.data + btf_sec.offset,
				    btf_sec.size, target->is_be);
	}

	if (map_file(external, path, false))
		return -1;
	if (external->size >= EI_NIDENT &&
	    !memcmp(external->data, ELFMAG, SELFMAG)) {
		struct elf_view elf;
		struct elf_section btf_sec, ids, symtab;
		uint32_t ids_index;
		int err;

		unmap_file(external);
		if (elf_open(&elf, path, false))
			return -1;
		err = elf_find_sections(&elf, &btf_sec, &ids, &ids_index,
					&symtab);
		if (err || !btf_sec.size) {
			elf_close(&elf);
			return -1;
		}
		/* Keep the mapping alive through the external file holder. */
		*external = elf.file;
		memset(&elf.file, 0, sizeof(elf.file));
		external->fd = external->fd < 0 ? -1 : external->fd;
		return btf_open_raw(btf, external->data + btf_sec.offset,
				    btf_sec.size, elf.is_be);
	}
	return btf_open_raw(btf, external->data, external->size, false);
}

int main(int argc, char **argv)
{
	const char *btf_path = NULL;
	const char *path;
	struct mapped_file external = { .fd = -1 };
	struct elf_section btf_sec, ids, symtab;
	struct symbol_list symbols = {};
	struct btf_view btf;
	struct elf_view elf;
	uint32_t ids_index;
	int opt, err = 1;

	while ((opt = getopt(argc, argv, "b:vh")) != -1) {
		switch (opt) {
		case 'b':
			btf_path = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
			usage(stdout, argv[0]);
			return 0;
		default:
			usage(stderr, argv[0]);
			return 1;
		}
	}
	if (optind + 1 != argc) {
		usage(stderr, argv[0]);
		return 1;
	}
	path = argv[optind];
	if (elf_open(&elf, path, true))
		goto out;
	if (elf_find_sections(&elf, &btf_sec, &ids, &ids_index, &symtab) ||
	    !ids.size || !symtab.size) {
		fprintf(stderr, "FAILED: %s lacks .BTF_ids or a symbol table\n", path);
		goto out_elf;
	}
	if (get_btf_view(btf_path, &elf, &external, &btf)) {
		fprintf(stderr, "FAILED: cannot load BTF for %s\n", path);
		goto out_elf;
	}
	if (collect_symbols(&elf, &ids, ids_index, &symtab, &symbols)) {
		fprintf(stderr, "FAILED: cannot collect .BTF_ids symbols\n");
		goto out_external;
	}
	if (verbose)
		printf("Found %zu BTF ID symbols in %s\n", symbols.count, path);
	if (resolve_symbols(&elf, &ids, &btf, &symbols))
		goto out_external;
	if (msync(elf.file.data, elf.file.size, MS_SYNC)) {
		fprintf(stderr, "FAILED: msync %s: %s\n", path, strerror(errno));
		goto out_external;
	}
	err = 0;

out_external:
	symbols_free(&symbols);
	unmap_file(&external);
out_elf:
	elf_close(&elf);
out:
	return err;
}
