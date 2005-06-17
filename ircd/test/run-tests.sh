#! /bin/sh

set -e
srcdir=`dirname $0`
ircdir=$1

cp ${srcdir}/ircd-t1.conf ircd-t1.conf
cp ${srcdir}/ircd-t2.conf ircd-t2.conf
echo "Testing one-shot ircd invocations."
${ircdir}/ircd -v
${ircdir}/ircd -x 6 -k -d . -f ircd-t1.conf -c user@127.0.0.1
echo "Starting ircd."
${ircdir}/ircd -d . -f ircd-t1.conf
${ircdir}/ircd -d . -f ircd-t2.conf
sleep 10
# stats-1 is out of alphabetical order to avoid triggering IPcheck.
for script in channel-1 client-1 commands-1 feature-1 gline-1 stats-1 jupe-1 kill-block-1 ; do
  echo "Running test $script."
  ${srcdir}/test-driver.pl -D ${srcdir}/${script}.cmd 2> ${script}.log
done
echo "Sending signals to server."
cp ${srcdir}/ircd-t1-2.conf ircd-t1.conf
kill -HUP `cat ircd-t1.pid`
sleep 1
kill -INT `cat ircd-t1.pid`
# A long sleep is necessary to make the server flush its IPcheck entries.
sleep 610
kill -TERM `cat ircd-t1.pid` `cat ircd-t2.pid`
sleep 1
${ircdir}/ircd -? || true
