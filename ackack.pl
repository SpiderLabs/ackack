#!/usr/bin/perl

=header
    ackack - A tool to manage network sessions
	Created by Steve Ocepek
    Copyright (C) 2009-2010 Trustwave Holdings, Inc.
 
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
=cut

#use strict;
#use warnings;
use Net::Pcap;
use AnyEvent;
use EV;
#use AnyEvent::Impl::Perl;
use IO::Handle;
use Net::Whois::IANA;
use YAML;
use Net::IP;
use Net::Syslog;

# Pcap vars
my $pcap;
my $err;
my $snaplen = 96;
my $promisc = 1;
my $to_ms = 15;
my $filter;
my $filter_str = 'tcp and tcp[tcpflags] & (tcp-ack | tcp-rst) !=0';
my ($address, $netmask);
my $pktsum;
my $pkt;
my %header;
my $packet;
my %devinfo;
my %pcapstats;
my $index = 1;
my $smtimer = 0;
# Months for logging
my @month = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);


# TCP Flags
my $FIN = 0x01;
my $SYN = 0x02;
my $RST = 0x04;

# Data offsets
my $os_srcip = 26;
my $os_dstip = 30;
my $os_srcpt = 34;
my $os_dstpt = 36;
my $os_flags = 46;

# Session hash
# key: source:sourceport:server:serverport
# [0]: FIN status
# [1]: Inactivity timeout
# [2]: Policy timeout
# [3]: Source group
# [4]: Server group
# [5]: Alert status
my %sessions;
my @deletions;


# Load configs
my $config = YAML::LoadFile('config.yml');
my $group = YAML::LoadFile('group.yml');
my $policy = YAML::LoadFile('policy.yml');

# Settings
my $timeout = $config->{timeout};
my $fin_timeout = $config->{fin_timeout};
my $session_report = $config->{session_report};
my $report_all = $config->{report_all};
my $syslog = $config->{syslog};
my $syslog_facility = $config->{syslog_facility};
my $syslog_alert = $config->{syslog_alert};

# Defaults
$syslog = "127.0.0.1" unless defined($syslog);
$syslog_facility = "local5" unless defined($syslog_facility);
$session_report = 1 unless defined($session_report);
$report_all = 1 unless defined($report_all);
$fin_timeout = "1" unless defined($fin_timeout);
$timeout = "20" unless defined($timeout);

# Patch Net::Whois::IANA - default server listing includes
# an ARIN server that refuses connections
# Tried using mywhois feature but that didn't seem to work right

$Net::Whois::IANA::IANA{'arin'} = [['whois.arin.net',43,30],];

# Listening interface
# Specify on command line or prompt
my $dev;
if ($ARGV[0]) {
	$dev = $ARGV[0];
}
else {
	# Show available devices, allow user to choose
	# TODO allow int specified on ARGV
	my @devs = Net::Pcap::findalldevs(\$err, \%devinfo);
	if ($devs[0]) {
		print "\n";
		print "Please choose an interface to listen on\n\n";


		for my $d (@devs) {
		    print "$index: $d - $devinfo{$d}\n";
		    $index++;
		}

		print "\n> ";
		my $choice = <STDIN>;
		chomp ($choice);

		$dev = $devs[$choice-1];
	}
	else {
		print "No interfaces found. Ensure that current user has admin/root priveleges.\n";
		exit;
	}
	
}

# Get net info for device to create filter
if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
    die 'Unable to look up device information for ', $dev, ' - ', $err;
}
# Open device
$pcap = Net::Pcap::open_live($dev, $snaplen, $promisc, $to_ms, \$err);
unless ($pcap) {
    die "Error opening live: $err\n";
}


# Compile and set filter
Net::Pcap::compile($pcap, \$filter, $filter_str, 1, $netmask) &&
    die 'Unable to compile packet capture filter';
Net::Pcap::setfilter($pcap, $filter) &&
    die 'Unable to set packet capture filter';

# Process groups
# Do WHOIS stuff here
my %groupmap;
my $iana = new Net::Whois::IANA;
foreach my $x (keys(%{$group})) {
	foreach my $y (@{${$group}{$x}}) {
		if ($y =~ m/\((.*)\)/) {
			print "Performing WHOIS query for $1\n";
			$iana->whois_query(-ip=>$1);
			unless ($iana->cidr()) {die "WHOIS network address invalid: $1";}
			foreach my $z (@{$iana->cidr()}) {
				my $ip = new Net::IP ($z) or die "WHOIS network address invalid: $y";
				push(@{$groupmap{$x}}, $ip);
				$iana = new Net::Whois::IANA;
			}
		}
		else {
		my $ip = new Net::IP ($y) or die "Network address invalid: $y";
		push(@{$groupmap{$x}}, $ip);
		}
	}
	}

# Don't set nonblock on Windows unless you like high CPU utilization
unless ($^O eq 'MSWin32') {
        Net::Pcap::pcap_setnonblock($pcap, 1, \$err);
}

sub event {
	# In charge of dispatching events
	# Takes args: 
	# TYPE - OPEN, CLOSE, TIMEOUT, ALERT
	# SESSION - srcip:srcport:srvip:srvport
	# SOURCE GROUP
	# SERVER GROUP
	my @time = localtime;
	my $event = 
		"<" . 
		"$month[$time[4]]  $time[3] " . sprintf("%02d:%02d:%02d",$time[2],$time[1],$time[0]) . "," .
		$_[0] . "," .
		$_[1] . "," .
		$_[2] . "," .
		$_[3] .
		">";
	# Print it
	print "$event\n";
	# Send syslog if event configured
	if ($syslog_alert->{$_[0]}) {
		# Send syslog message
		my $s=new Net::Syslog(Facility=>$syslog_facility,Priority=>$syslog_alert->{$_[0]});
		$s->send($event);
	}
}

sub process_packet {
    # Since this gets executed on every packet, leaner is better
	# This needs to be cleaned up and optimized, split policy setting into another watcher
	my ($user_data, $header, $pkt) = @_;
	my ($flag,$server,$source,$server_port,$source_port,$dir,$fa);
	my @time = localtime;
	# Figure out what kind of packet it is
	my $flags = (unpack("n", (substr($pkt, $os_flags, 2)))) & 0x00ff;

	# This logic does not account for illegal combinations
	# but timeouts will terminate non-existant connections
	# Any ideas for optimizations? sprintf might be heavy...
	my $srcip = sprintf("%d.%d.%d.%d",
		ord (substr($pkt, $os_srcip, 1)),
		ord (substr($pkt, $os_srcip+1, 1)),
		ord (substr($pkt, $os_srcip+2, 1)),
		ord (substr($pkt, $os_srcip+3, 1)));

	my $dstip = sprintf("%d.%d.%d.%d",
		ord (substr($pkt, $os_dstip, 1)),
		ord (substr($pkt, $os_dstip+1, 1)),
		ord (substr($pkt, $os_dstip+2, 1)),
		ord (substr($pkt, $os_dstip+3, 1)));

	my $srcport = unpack("n", (substr($pkt, $os_srcpt, 2)));
	my $dstport = unpack("n", (substr($pkt, $os_dstpt, 2)));
	
	# With SYN+ACK we know server and source
	# $dir - IN is 0, OUT is 1
	if ($flags & $SYN) {
		$flag = "SA";
		$dir = 0;
		# convert IPs into dotted quad
		# source is dest because syn+ack is an answer
		$server = $srcip;
		$source = $dstip;
		$server_port = $srcport;
		# "Source" port is dstport because this is response packet. it's kooky
		$source_port = $dstport;
	}
	# Not SYN+ACK
	else {
		if ($flags & $RST) { $flag = "RA"; }
		elsif ($flags & $FIN) { $flag = "FA"; }
		else { $flag = "A"; }
		
		# Only do guesswork if no record exists already
		if ($sessions{"$srcip:$srcport:$dstip:$dstport"}) {
			$source = $srcip;
			$server = $dstip;
			$source_port = $srcport;
			$server_port = $dstport;
			$dir = 1;
		}
		elsif ($sessions{"$dstip:$dstport:$srcip:$srcport"}) {
			$source = $dstip;
			$server = $srcip;
			$source_port = $dstport;
			$server_port = $srcport;
			$dir = 0;
		}
		else {
			# We have to figure out server and source otherwise
			# Cheesy method used here - lower port is server, higher is client, this should be last resort
			# Might get screwed up with Skype, P2P
			# TODO: Server port list
			# TODO: TCP SYN test on each - requires separate watcher
			my $res = $srcport <=> $dstport;
			if ($res == -1) {($server,$source,$server_port,$source_port,$dir) = ($srcip,$dstip,$srcport,$dstport,0);}
			if ($res == 1) {($source,$server,$source_port,$server_port,$dir) = ($srcip,$dstip,$srcport,$dstport,1);}
			#ummm if they're the same, first one wins.... fix me someday you behavioral analysis genius, you
			if ($res == 0) {($source,$server,$source_port,$server_port,$dir) = ($srcip,$dstip,$srcport,$dstport,1)};
		}
	}
	
	# Don't increment timer if in FIN state
	if (($sessions{"$source:$source_port:$server:$server_port"}->[1]) and ($sessions{"$source:$source_port:$server:$server_port"}->[1] == 0x03)) {
		return;
	}
	
	if ($flag eq "FA") {
		if ($dir == 1) {
			$fa = 0x01;
		} else {
			$fa = 0x02;
		}
		# OR fa with current value, 0x03 means FIN+ACKs recvd from both sides and kill session
		$sessions{"$source:$source_port:$server:$server_port"}->[1] |= $fa;
		$sessions{"$source:$source_port:$server:$server_port"}->[0] = time + ($fin_timeout * 60);
	}
	elsif ($flag eq "RA") {
		# RST - clobber the connection, overloading FIN control for now
		$sessions{"$source:$source_port:$server:$server_port"}->[1] = 0x03;
		$sessions{"$source:$source_port:$server:$server_port"}->[0] = time + ($fin_timeout * 60);
	} 
	else {
		# Reset timeout value
		$sessions{"$source:$source_port:$server:$server_port"}->[0] = time + ($timeout * 60);
		unless ($sessions{"$source:$source_port:$server:$server_port"}->[1]) { $sessions{"$source:$source_port:$server:$server_port"}->[1] = 0; }
	}
}

# Doing timer to work around borked blocking behavior on some BPF devices
# (Mac OS X, some BSD)
my $pcaploop = AnyEvent->timer (after => 0, interval => .001, cb => sub {
	  Net::Pcap::pcap_dispatch($pcap, 1, \&process_packet, "user data");
   });

my $sessionmgr = AnyEvent->timer (after => 10, interval => 10, cb => sub {
	# Delete closed, timed out sessions from last run first
	# This helps prevent extra packet race conditions from recreating FIN sessions
	while(scalar(@deletions)) {
		# Session end events
		# If FIN set to 0x03, it's a CLOSE
		# Otherwise, it's a TIMEOUT
		my $x = pop(@deletions);
		if ($sessions{$x}->[1] == 0x03) {
			event("CLOSE", $x, $sessions{$x}->[3], $sessions{$x}->[4]);
		}
		else {
			event("TIMEOUT", $x, $sessions{$x}->[3], $sessions{$x}->[4]);
		}
		delete $sessions{$x};
	}
	foreach my $x (keys(%sessions)) {
		# Apply groups
		# If it's new, [2] is unset
		unless (defined($sessions{$x}->[2])) {
			# Go through localmap and find overlap with IP object
			my @ips = split(':', $x);
			my ($srcip,$srvip) = ($ips[0],$ips[2]);
			my ($srcgroup,$srvgroup);
			# groupmap contains groupname => [Net::IP obj1, Net::IP obj2, ...]
			foreach my $y (keys(%groupmap)) {
				foreach my $z (@{$groupmap{$y}}) {
					unless ($srcgroup) {
						#print "srcip is $srcip and z is $z\n";
						if (new Net::IP($srcip)->overlaps($z)) {
							$srcgroup = $y;
						}
					}
					unless ($srvgroup) {
						if (new Net::IP($srvip)->overlaps($z)) {
							$srvgroup = $y;
						}
					}
				}
			}
			# Set alert timer [2]
			if ($srcgroup) {
				$sessions{$x}->[3] = $srcgroup;
			} else {$sessions{$x}->[3] = 'X';}
			if ($srvgroup) {
				$sessions{$x}->[4] = $srvgroup;
			} else {$sessions{$x}->[4] = 'X';}
			
			# If policy exists, apply duration
			if (defined($$policy{$sessions{$x}->[3]}{$sessions{$x}->[4]})) {
				$sessions{$x}->[2] = time + (($$policy{$sessions{$x}->[3]}{$sessions{$x}->[4]}) * 60);
				#print "duration applied: $x";
			}
			else {
				$sessions{$x}->[2] = 0;
			}
			# OPEN event
			event("OPEN", $x, $sessions{$x}->[3], $sessions{$x}->[4]);
		}
		
		# Schedule for deletion if timeout is passed
		if ($sessions{$x}->[0] < time) {
			push (@deletions,$x); 
		}
		# Eval alert status, unless
		# there's no policy ([2] == 0), or
		# FIN timeout is occurring ([1] == 3), or
		# Alert already sent ([5] is defined)
		#unless (($sessions{$x}->[2] == 0) or ($sessions{$x}->[1] == 0x03) or ($sessions{$x}->[5])) {
		unless (($sessions{$x}->[2] == 0) or ($sessions{$x}->[5])) {
			if ($sessions{$x}->[2] <= time) {
				event("ALERT", $x, $sessions{$x}->[3], $sessions{$x}->[4]);
				# Alert status is 1
				$sessions{$x}->[5] = 1;
			}
		}
	}

	# Do status here every x number of times
	if (($smtimer < time) and ($session_report)) {
		my @time = localtime;
		my @report;
		# every program should call you commander
		print "\n-=SESSION MANAGER REPORTING COMMANDER=-\n";
		print "Time is now: $month[$time[4]]  $time[3] " . sprintf("%02d:%02d:%02d",$time[2],$time[1],$time[0]) ."\n";
		Net::Pcap::pcap_stats($pcap,\%pcapstats);
		print "Packets Recv: " . $pcapstats{ps_recv} . " Drop: " . $pcapstats{ps_drop} . "\n";
		print "-" x 78 . "\n";
		
			
		foreach my $x (keys(%sessions)) { 
			my @y = split(':', $x);
			my $alert;
			if ($sessions{$x}->[5]) {
				$alert = "Y";
			}
			else {
				$alert = "N";
			}
			if ($alert eq 'Y' or $report_all) {
				push (@report, sprintf ("%-16s %-8s %-10s %-16s %-8s %-10s %1s", $y[0], $y[1], $sessions{$x}->[3], $y[2], $y[3], $sessions{$x}->[4], $alert) . "\n");
			}
		}
		if (scalar(@report)) {
			print sprintf ("%-16s %-8s %-10s %-16s %-8s %-10s %1s", qw(Source SrcPort SrcGroup Server SrvPort SvrGroup !)) . "\n";
			foreach my $x (@report){
				print $x;
			}
		}
		else {
			print "\nNOTHING TO REPORT\n";
		}
		
		print "\n-=END OF LINE=-\n\n";
		$smtimer = time + ($session_report * 60);	
	}
});

#AnyEvent::Impl::Perl::loop;
EV::loop;