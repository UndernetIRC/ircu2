
CPPFLAGS = -I../../include -I../../config
CFLAGS   = -g -Wall

TESTPROGS = \
	ircd_chattr_t \
	ircd_string_t

all: ${TESTPROGS}
 
ircd_chattr_t: ircd_chattr_t.o ../ircd_string.o
	${CC} -o $@ $^

ircd_string_t: ircd_string_t.o ../ircd_string.o
	${CC} -o $@ $^

.PHONY: clean

clean:
	rm -f core *.o ${TESTPROGS}
