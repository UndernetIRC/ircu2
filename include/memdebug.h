/* This file should only ever be included from ircd_alloc.h */

void *dbg_malloc(size_t size, const char *type, const char *file, int line);
void *dbg_malloc_zero(size_t size, const char *type, const char *file, int line);
void *dbg_realloc(void *ptr, size_t size, const char *file, int line);
void dbg_free(void *ptr, const char *file, int line);
size_t fda_get_byte_count(void);
size_t fda_get_block_count(void);
