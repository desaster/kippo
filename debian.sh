#! /bin/sh
### BEGIN INIT INFO
# Provides:			   kippo
# Required-Start:		 $remote_fs $syslog $network mysql
# Required-Stop:		  $remote_fs $syslog $network
# Default-Start:		  2 3 4 5
# Default-Stop:		   0 1 6
# Short-Description:	  SSH honeypot
# Description:			SSH honeypot
### END INIT INFO

# Author: Kevin Valk <kevin@kevinvalk.nl>
#

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/usr/local/bin:$PATH
DESC="Kippo SSH honeypot"
NAME=kippo
DAEMON_DIR=/var/software/$NAME
DAEMON=$DAEMON_DIR/$NAME.tac
DAEMON_ARGS=""
TWISTD=/usr/local/bin/twistd
PIDFILE=$DAEMON_DIR/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME
LOGFILE=log/$NAME.log

# Exit if the package is not installed
[ -x $TWISTD ] || exit 0

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
. /lib/lsb/init-functions

VERBOSE=yes

#
# Function that starts the daemon/service
#
do_start()
{
	# Return
	#   0 if daemon has been started
	#   1 if daemon was already running
	#   2 if daemon could not be started
	start-stop-daemon --start --quiet --pidfile $PIDFILE --chdir $DAEMON_DIR --chuid $NAME:$NAME --exec $TWISTD --test > /dev/null \
			|| return 1
	start-stop-daemon --start --quiet --pidfile $PIDFILE --chdir $DAEMON_DIR --chuid $NAME:$NAME --exec $TWISTD -- \
						--pidfile=$PIDFILE \
						--logfile=$LOGFILE \
						-y $DAEMON \
						$DAEMON_ARGS \
			|| return 2
	# Add code here, if necessary, that waits for the process to be ready
	# to handle requests from services started subsequently which depend
	# on this one.  As a last resort, sleep for some time.
}

#
# Function that stops the daemon/service
#
do_stop()
{
	# Return
	#   0 if daemon has been stopped
	#   1 if daemon was already stopped
	#   2 if daemon could not be stopped
	#   other if a failure occurred
	start-stop-daemon --stop --quiet --chdir $DAEMON_DIR --chuid $NAME:$NAME --retry=TERM/30/KILL/5 --pidfile $PIDFILE
	RETVAL="$?"
	[ "$RETVAL" = 2 ] && return 2
	# Wait for children to finish too if this is a daemon that forks
	# and if the daemon is only ever run from this initscript.
	# If the above conditions are not satisfied then add some other code
	# that waits for the process to drop all resources that could be
	# needed by services started subsequently.  A last resort is to
	# sleep for some time.
	start-stop-daemon --stop --quiet --chdir $DAEMON_DIR --chuid $NAME:$NAME --oknodo --retry=0/30/KILL/5 --exec $TWISTD
	[ "$?" = 2 ] && return 2
	# Many daemons don't delete their pidfiles when they exit.
	rm -f $PIDFILE
	return "$RETVAL"
}

case "$1" in
  start)
		[ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC " "$NAME"
		do_start
		case "$?" in
			0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
			2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
		esac
  ;;
  stop)
		[ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
		do_stop
		case "$?" in
			0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
			2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
		esac
  ;;
  status)
		status_of_proc "$TWISTD" "$NAME" && exit 0 || exit $?
		;;
  restart|force-reload)
		log_daemon_msg "Restarting $DESC" "$NAME"
		do_stop
		case "$?" in
			0|1)
				do_start
				case "$?" in
					0) log_end_msg 0 ;;
					1) log_end_msg 1 ;; # Old process is still running
					*) log_end_msg 1 ;; # Failed to start
				esac
			;;
			*)
				# Failed to stop
				log_end_msg 1
			;;
		esac
  ;;
  *)
		echo "Usage: $SCRIPTNAME {start|stop|status|restart|force-reload}" >&2
		exit 3
  ;;
esac

:
