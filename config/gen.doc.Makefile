. ./.config
. ./parse.none
mv ../doc/Makefile ../doc/Makefile.tmp
sed -e "s:^MANDIR=.*:MANDIR=$MANDIR:" \
    -e "s:^INSTALL *= *\.\..*:INSTALL=../config/install-sh -c:" \
    ../doc/Makefile.tmp > ../doc/Makefile
$RM -f ../doc/Makefile.tmp
