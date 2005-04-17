#!/bin/sh
# linesync.sh, Copyright (c) 2002 Arjen Wolfs
# 20020604, sengaia@undernet.org
# 20050417, daniel@undernet.org  - modified for u2.10.12
# $Id$
#
# The code contained is in this file is licenced under the terms
# and conditions as specified in the GNU General Public License.
#
# linesync.sh - centralized ircd.conf updates.
# The purpose of this little shell script is to allow a section of an ircd.conf to be 
# updated from a central location. Hence it is intended to facilitate the automated 
# distribution of Kill, Jupe, Quarantine and Uworld lines; or any other .conf lines you 
# may wish to keep synchronized accross all servers on a network.
#
# This script will download a file called linesync from a specified web server (see 
# below for configuration), and calculate an md5sum from it. It will then download
# a file called linesync.sum from a configurable number of other web servers and
# compare the contents of these files against the checksum calculated. If any of the
# downloaded checksums mismatch, the program will abort. This provides security to
# the centralized update mechanism - in order for it to be compromised, multiple
# web servers would have to compromised.
#
# If all checksums match, the script inspects the .conf lines contained within the 
# downloaded file. If any .conf lines are found that are not specifically allowed,
# the program will abort. This will prevent malicious/dangerous .conf lines (such as
# Operator or Connect lines) from being inserted into ircd.conf.
#
# If all the checks mentioned above are passed, the script checks ircd.conf for a section
# that begins with "# BEGIN LINESYNC", and ends with "# END LINESYNC". The section contained
# between these two comments is the section maintained by this program. If these lines are not
# found in the ircd.conf, they will be appended to it.
# Next, the script will build a new ircd.conf by removing all lines present between the two
# commented lines mentioned above, and replace them with the contents of the file downloaded.
# 
# Once this has been completed, ircd.conf is backed up and replaced with the newly built version,
# and ircd will be rehashed. 
#
# Configuration: This script requires two parameters - the full path to your ircd.conf, and the
# full path to your ircd.pid. It will look for a configuration file called linesync.conf in the
# same directory as ircd.conf. See the included sample linesync.conf for information on how to
# set it up. Obviously, you will need to have web server(s) to use for the distribution of your
# .conf update and checksums. This script requires the presence of wget and md5sum, and various
# other programs that should be present by default on any Unix system. 
#
# This program should be run from crontab, i.e something like:
# 0 0 * * * /home/irc/bin/linesync.sh /home/irc/lib/ircd.conf /home/irc/lib/ircd.pid
#
# This program has been tested on and works on FreeBSD, Solaris, and Linux.
# md5sum is included in GNU textutils.
#
#	Good Luck!
#	Arjen Wolfs (sengaia@undernet.org), June 9 2002.
#

# This checks for the presence of an executable file in $PATH
locate_program() {
        if [ ! -x "`which $1 2>&1`" ]; then
                echo "You don't seem to have $1. Sorry."
                exit 1
        fi
}

# This checks for the presence of any file
check_file() {
        if [ ! -f "$1" ]; then
                echo "There doesn't appear to be a $1. Sorry."
                exit 1
        fi
}

# Try to find programs we will need
locate_program wget && locate_program egrep && locate_program diff

# try to find GNU awk
awk_cmd=`which gawk`
if [ $? -ne 0 ]; then
        awk_cmd=""
fi

# try to find an appropriate md5 program
# BSD md5 capability courtesy of spale
md5_cmd=`which md5sum`
if [ -z "$md5_cmd" ]; then
	md5_cmd=`which md5`
	if [ -z "$md5_cmd" ]; then
		echo "No MD5 capable programs found (I looked for md5sum and md5)."
		exit
	else
		md5_cmd="$md5_cmd -q"
	fi
fi

if [ -z "$awk_cmd" ]; then
	locate_program awk
	is_gawk=`echo | awk --version | head -1 | egrep '^GNU.+$'`
	if [ -z "$is_gawk" ]; then
		echo "Your version of awk is not GNU awk. Sorry."
		exit 1
	fi
	awk_cmd="awk"	
fi

# Check for required command line parameters
if [ -z "$1" -o -z "$2" ]; then
        echo "Usage: $0 <conf_path> <pid_path>"
        echo "      <conf_path>     Full path to ircd.conf (/home/irc/lib/ircd.conf)"
        echo "      <pid_path>      Full path to ircd.pid (/home/irc/lib/ircd.pid)"
        exit 1
fi

# check and set up stuff
diff_cmd="diff"
cpath=$1
ppath=$2
check_file $cpath
dpath=`dirname $cpath`
lpath="$dpath/linesync.conf"
check_file $lpath
save_dir=$PWD; cd $dpath
tpath=$PWD; cd $save_dir
tmp_path="$dpath/tmp"
mkdir $tmp_path > /dev/null 2>&1

# load and check configuration
. $lpath
if [ -z "$LINE_SERVER" -o -z "$LINE_CHECK" -o -z "$ALLOWED_LINES" ]; then
	echo "Please setup $lpath correctly."
	exit 1
fi

# Not all versions of date support %s, work around it
TS=`date +%Y%m%d%H%M%S`
TMPFILE="$tmp_path/linesync.$TS"
LSFILE="$LINE_SERVER""linesync"
# Attempt to download our .conf update
wget --cache=off --quiet --output-document=$TMPFILE $LSFILE > /dev/null 2>&1
if [ ! -s "$TMPFILE" ]; then
        echo "Unable to retrieve $LSFILE. Sorry."
	rm $TMPFILE > /dev/null 2>&1
        exit 1
fi

# Check whether the file contains any disallowed .conf lines
bad_lines=`egrep '^[^'$ALLOWED_LINES'|#]+' $TMPFILE`
if [ ! -z "$bad_lines" ]; then
        echo "The file downloaded in $TMPFILE contains the following disallowed line(s):"
        echo $bad_lines
        exit 1
fi

# Check whether somebody tried to sneak a second block onto some line
bad_lines=`egrep -i '}[ 	]*;[ 	]*[a-z]+[ 	]*{' $TMPFILE`
if [ ! -z "$bad_lines" ] ; then
	echo "The file downloaded in $TMPFILE contains the following multi-block line(s):"
        echo $bad_lines
        exit 1
fi

# check our ircd.conf
ircd_setup=`egrep '^# (BEGIN|END) LINESYNC$' $cpath|wc -l`
if [ $ircd_setup != 2 ]; then
	cp $cpath $cpath.orig
	echo "Performing initial merge on $cpath, original file saved as $cpath.orig."
	
        echo "# Do NOT remove the following line, linesync.sh depends on it!" >> $cpath
        echo "# BEGIN LINESYNC" >> $cpath
        echo "# END LINESYNC" >> $cpath
        echo "# Do not remove the previous line, linesync.sh depends on it!" >> $cpath

	# Do an initial merge to remove duplicates
	inpath="$tmp_path/linesync.tmp.$TS"
	$awk_cmd '
	{
                if (!loaded_template) {
                        command="cat " tempfile; tlines=0;
                        while ((command | getline avar) > 0) { template[tlines]=avar; tlines++ }
                        close(command)
                        loaded_template++
                }
		dup_line=0
                for (i=0; i<tlines; i++) {
                        if (tolower($0)==tolower(template[i])) { dup_line++; break }
                }
		if (!dup_line) print $0
        } ' tempfile=$TMPFILE < $cpath > $inpath
else
	inpath=$cpath
fi

# Get the checksum
CKSUM=`$md5_cmd $TMPFILE|cut -d' ' -f1`

check_file="$tmp_path/linesync.sum.$TS"
for ck_server in $LINE_CHECK; do
	sumfile="$ck_server""linesync.sum"
	wget --cache=off --quiet --output-document=$check_file $sumfile > /dev/null 2>&1
	if [ ! -s "$check_file" ]; then
		echo "Unable to retrieve checksum from $sumfile"
		exit 1	
	fi
	if [ "$CKSUM" != "`cat $check_file`" ]; then
		echo "Checksum retrieved from $sumfile does not match!"
		exit 1
	fi
	rm -f $check_file
done
# It all checks out, proceed...

# Replace the marked block in ircd.conf with the new version

$awk_cmd ' 
$0=="# BEGIN LINESYNC" { chop++; print; next }
$0=="# END LINESYNC" {
        command="cat " syncfile
        while ((command | getline avar) > 0) { print avar }
        close(command)
        chop--
}
{ if (!chop) print $0 }
' syncfile=$TMPFILE < $inpath > $tmp_path/linesync.new.$TS

# run a diff between current and new confs to see if we updated anything
# no point sending the ircd a -HUP if this is not needed, especially on a
# busy network, such as Undernet.
diff=`$diff_cmd $cpath $tmp_path/linesync.new.$TS`
if [ ! -z "$diff" ]; then
	# Changes were detected

	# Back up the current ircd.conf and replace it with the new one
	cp $cpath  $dpath/ircd.conf.bk
	cp $tmp_path/linesync.new.$TS $cpath

	# Rehash ircd (without caring wether or not it succeeds)
	kill -HUP `cat $ppath 2>/dev/null` > /dev/null 2>&1
fi

# (Try to) clean up
rm -rf $tmp_path > /dev/null 2>&1

# That's it...
