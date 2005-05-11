#! /bin/sh
set -e
srcdir=$1
for script in channel-1 client-1 stats-1 gline-1 ; do
  echo "Running test $script."
  ${srcdir}/test-driver.pl ${srcdir}/${script}.cmd
done
echo "Terminating server."
${srcdir}/test-driver.pl ${srcdir}/die.cmd
../ircd -?
../ircd -v
../ircd -x 6 -k -d ${srcdir} -f ircd-t1.conf -c user@127.0.0.1
