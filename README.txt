 ______     ______     __  __       .- -.-. -.- .- -.-. -.-
/\  __ \   /\  ___\   /\ \/ /     ______     ______     __  __
\ \  __ \  \ \ \____  \ \  _"-.  /\  __ \   /\  ___\   /\ \/ /
 \ \_\ \_\  \ \_____\  \ \_\ \_\ \ \  __ \  \ \ \____  \ \  _"-. 
  \/_/\/_/   \/_____/   \/_/\/_/  \ \_\ \_\  \ \_____\  \ \_\ \_\
                                   \/_/\/_/   \/_____/   \/_/\/_/


Released at Black Hat USA 2009

Steve Ocepek
socepek@trustwave.com
http://www.trustwave.com/spiderlabs

INTRODUCTION
============

Staring at netstat is great for chasing people away from my desk, but my
therapist says I need to make more friends, so I wrote this thing. It lets
you create groups of hosts and apply policy to the types of connections being
made between them.

Cool stuff includes:
o Detection of already-running sessions
o Policies based on session origination and session duration
o Group specification using subnet, range, or WHOIS queries
o Policy-generated Syslog alerts
o It calls you "Commander"


CONFIGURATION
=============

The following configuration files should reside within the same directory
as ackack.

config.yml
----------

This file is used to configure Syslog, and other miscellaneous options.

group.yml
---------

Contains group mappings in the form:

GroupName:
 - address 1
 - address 2

GroupName is alphanumeric, and allows whatever characters that the YAML
parser doesn't mind. Avoid using the name "X", which has the special meaning
"Unknown" in the policy section. Maybe I should check for this, but I have
a feeling at least one person is going to feel better about themselves after
defining the unknown.

Address can be in the form of:

A single IP: 192.168.1.5
A subnet:    192.168.1.0/24
A range:     192.168.1.5-192.168.1.10
or
A WHOIS network query: (204.13.200.166) 

The WHOIS query will return all IP addresses used by that specific entity
and include them as part of the specified group. This makes it easy to 
create groups for Instant Messaging apps and such, which tend to use large
numbers of servers. Be careful with this feature, though. If you start
including ISPs, you never know what might show up. It's a good idea to look
at the WHOIS result yourself before including an IP address here.

policy.yml
----------

This is where you specify the things that interest you. Policies take the form:

source: {server: duration, server: duration ... }

Both "source" and "server" must be defined in group.yml first. The exception
is "X", which means "Undefined". Think of X as a wildcard, except it only
represents things that are not listed in group.yml. You can create any number
of policies for each source by using a comma and adding another entry. It's
all YAML-compliant stuff.

A source is the originator of a session, where a server is the, um,
one serving it. For example, when you connect to a web server, your machine
is the source of the session because you initiated. The web server didn't
come to you. If it did, well that might be a good thing to catch using
a policy.

Duration allows you to specify how long a session runs before it's interesting.
Even moderately sized networks create numerous connections, so duration
lets us look for the more interesting longer-term ones. Think about that
pesky PC Remote Control software you've been trying to eradicate, and session
duration starts showing potential. The same goes for IRC bots, P2P, etc.

USAGE
=====

ackack.pl [interface]

If interface is not supplied, a prompt will appear to choose one. Ensure that
your user account has root/admin privileges necessary to sniff packets.

Binary versions of the program for Win32, Mac, and Linux are available
in the bin directory. Simply copy your binary to the main ackack directory
and execute.

EXAMPLES
========

Here are some examples to get you started.

group.yml
---------

# Define our subnet as "local"
local:
  - 192.168.1.0/24

# It's ok for people to use AOL IM, so lets group some of their IM servers
AOL IM:
  - (64.12.23.218)
  - (205.188.248.151)

# Our corporate web servers
servers:
  - 169.254.50.51-169.254.50.100

policy.yml
----------

# I've defined AOL, so let's alert when local connects to anything else
# for over 10 minutes
local: {X: 10}

# I don't like the idea of my servers initiating sessions
# It smells of sploits
servers: {X: 0, local: 0}

# Normal web browsing doesn't establish long-term sessions
# But bind shells do
X: {servers: 10}

BUGS
====

This version employs Port Guessing to determine Server and Source. This means
that the lower number port is assumed to be the Server. It actually works
most of the time, but P2P and some other apps (Steam) will sometimes throw
this off. If you see Server/Source flipped in some cases, just send me
aggro-mail and I'll scurry around faster.

Port Validation is scheduled for the next release, which is a lot less
cheesy.

Also, groups shouldn't overlap right now, unless you like dice games.

CREDITS/THANKS
==============

Thanks to Nick and Rob at Spiderlabs for their encouragement and for testing
this junk, and to Brian Lauer for his help with late night compiler
errors. Also big thanks to Marc Lehmann for the great EV and AnyEvent
packages, and for taking time to help me with Pcap and funky Mac BPF
file descriptors.

COPYRIGHT
=========

ackack - A tool to monitor network sessions
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
along with this program.  If not, see <http://www.gnu.org/licenses/>
