## What is the purpose of this program?

If you have two routers chained, and the first router delegates a prefix to the second one, the second one does not
recognize prefix changes immediately (e.g. if you have a dynamic IPv6-Prefix assigned by you ISP).  
This program listens to RouterAdvertisements from the first router and re-requests the delegated prefix if it detects
changes.  
Additionally, it will send RAs to make all devices delete the old, invalid IPv6 addresses (and the other IPv6 addresses
they got from this router).

## How does it work?

This program opens a raw socket on the `listen_interface` and waits for any RAs to arrive, filtering the source mac
by `upstream_mac`.  
Every time a RA is received, the program checks, if

- any prefix is advertised with a `preferred-lifetime` of zero (i.e. prefix should not be used anymore)
- or any given prefix is "new" (was not present in the last RA)
- or any prefix received with the last RA is missing in this RA

The found prefixes are filtered by the `prefixes_regex`.  
If anything remains after filtering, and

- it has a `preferred-lifetime` greater than zero
- or it has `preferred-lifetime` of zero and it was not received within the last 30 minutes

the programm will send RAs with a `preferred-lifetime` of zero on all of the `send_interfaces` for all prefixes set on
these interfaces, if they match at least one of the `prefixes.regex`.  
This tells all devices to forget all IPv6 addresses they derived from these prefixes.  
It will repeat these RAs for each delay value in `send_delays`. The first RA is always sent with a delay of 0.

After sending the first RA on each interface, the program will search for the DHCPv6 process and send a reload signal.  
It filters the processes by applying all values of `dhcpv6_process_filter` to the command of each process (so all must
match!). Use `ps aux` to find useful values.  
This will cause the process to re-request the delegated prefix or get a new one, if the old one is invalid.

## Install

1. Copy executable to `/usr/bin/dhcp6-prefix-fix`
2. Give executable `net_raw` and `kill` capability to allow raw sockets and sending signals to other processes without
   root
   privileges: `sudo setcap "cap_net_raw=ep cap_kill=ep" /usr/bin/dhcp6-prefix-fix`
3. Copy service file to `/etc/systemd/system` or somewhere similar
4. Reload systemd
5. Copy config file to `/etc/dhcp6-prefix-fix.json`
6. Adjust config file
7. Enable and start service

## Configuration

The config file has the following fields:

|         Setting         |       Type       |             Example             | Explanation                                                                |
|:-----------------------:|:----------------:|:-------------------------------:|:---------------------------------------------------------------------------|
|   `listen_interface`    |      String      |             `eth0`              | The program will listen on this interface for RAs from the upstream router |
|     `upstream_mac`      |      String      |       `ba:c8:e2:e8:6c:01`       | Only RAs with this mac as source mac are accepted                          |
|    `prefixes_regex`     |      String      | <code>2001:.\*\|fd00:.\*</code> | Only advertised prefixes matching this regex are used                      |
|    `send_interfaces`    |    see below     |                                 | Which interfaces should be used to send RAs for the invalid prefixes       |
| `dhcpv6_process_filter` | Array of Strings |       `["dhcpv6","eth0"]`       | Search filter for the dhcpv6 process; all must match                       |

<br>

`send_interfaces` is an array (list) of the following:

|    Setting    |       Type        |   Example   | Explanation                                                                                                                            |
|:-------------:|:-----------------:|:-----------:|:---------------------------------------------------------------------------------------------------------------------------------------|
|    `name`     |      String       |   `eth1`    | Which interface should be used to send the RAs                                                                                         |
| `send_delays` | Array of unit > 0 | `[1,1,2,3]` | Configure delays of the RAs to send.<br/>Delay of 0 is always included.<br/>Add up: `[1,1,2,3]` will send RAs on seconds 0, 1, 2, 4, 7 |
|  `prefixes`   |     see below     |             | Which ips on this interface should be sent in the RAs as invalid prefixes                                                              |

<br>

`prefixes` is an array (list) of the following data structure:

| Setting  |  Type  |             Example             | Explanation                                                |
|:--------:|:------:|:-------------------------------:|:-----------------------------------------------------------|
| `regex`  | String | <code>2001:.\*\|fd00:.\*</code> | The RAs will contain all prefixes which match this regex   |
| `length` |  uint  |              `64`               | Length of the prefix in the RAs (netmask in cidr notation) |

## Build the mips binary yourself

Thanks to Defelo, this command will build you the binary for mips (e.g. ER-X) without needing to set up the whole build
environment on your machine.  
Just clone the repo, and run this command inside the root of the repo.  
You need docker installed and you may need to use `sudo`.  
The binary will be put into the target folder.  
`docker run -it --rm -v $PWD:/build ghcr.io/thecataliastnt2k/mips-cross-builder`
