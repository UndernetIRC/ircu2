. ./.config
. ./parse.none
mv ../ircd/Makefile ../ircd/Makefile.tmp
sed -e "s:^CC=.*:CC=$CC:" \
    -e "s:^CFLAGS=.*:CFLAGS=$CFLAGS:" \
    -e "s:^CPPFLAGS=.*:CPPFLAGS=$CPPFLAGS:" \
    -e "s:^LDFLAGS=.*:LDFLAGS=$LDFLAGS:" \
    -e "s:^IRCDLIBS=.*:IRCDLIBS=$IRCDLIBS:" \
    -e "s:^IRCDMODE=.*:IRCDMODE=$IRCDMODE:" \
    -e "s:^IRCDOWN=.*:IRCDOWN=$IRCDOWN:" \
    -e "s:^IRCDGRP=.*:IRCDGRP=$IRCDGRP:" \
    -e "s:^BINDIR=.*:BINDIR=$BINDIR:" \
    -e "s:^SYMLINK=.*:SYMLINK=$SYMLINK:" \
    -e "s:^INCLUDEFLAGS=.*:INCLUDEFLAGS=$INCLUDEFLAGS:" \
    -e "s:^DPATH=.*:DPATH=$DPATH:" \
    -e "s:^MPATH=.*:MPATH=$MPATH:" \
    -e "s:^RPATH=.*:RPATH=$RPATH:" \
    -e "s:^INSTALL *= *\.\..*:INSTALL=../config/install-sh -c:" \
    ../ircd/Makefile.tmp > ../ircd/Makefile
$RM -f ../ircd/Makefile.tmp
