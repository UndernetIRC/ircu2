/*
 * fileio.h
 *
 * $Id$
 */
#ifndef INCLUDED_fileio_h
#define INCLUDED_fileio_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>          /* size_t */
#define INCLUDED_sys_types_h
#endif

struct stat;

/*
 * FileBuf is a mirror of the ANSI FILE struct, but it works for any
 * file descriptor. FileBufs are allocated when a file is opened with
 * fbopen, and they are freed when the file is closed using fbclose.
 */
typedef struct FileBuf FBFILE;

/*
 * open a file and return a FBFILE*, see fopen(3)
 */
extern FBFILE *fbopen(const char *filename, const char *mode);
/*
 * associate a file descriptor with a FBFILE*
 * if a FBFILE* is associated here it MUST be closed using fbclose
 * see fdopen(3)
 */
extern FBFILE *fdbopen(int fd, const char *mode);
/*
 * close a file opened with fbopen, see fclose(3)
 */
extern void fbclose(FBFILE * fb);
/* 
 * return the next character from the file, EOF on end of file
 * see fgetc(3)
 */
extern int fbgetc(FBFILE * fb);
/*
 * return next string in a file up to and including the newline character
 * see fgets(3)
 */
extern char *fbgets(char *buf, size_t len, FBFILE * fb);
/*
 * write a null terminated string to a file, see fputs(3)
 */
extern int fbputs(const char *str, FBFILE * fb);
/*
 * return the status of the file associated with fb, see fstat(3)
 */
extern int fbstat(struct stat *sb, FBFILE * fb);

#endif /* INCLUDED_fileio_h */
