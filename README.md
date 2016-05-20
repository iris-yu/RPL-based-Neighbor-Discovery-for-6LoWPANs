# RPL-based-Neighbor-Discovery-for-6LoWPANs
Realization of various IPv6 neighbor discovery mechanisms for constrained devices according to specifications of RFC 6775, RFC 4861, and 'RPL-based neighbor discovery protocol' proposed by myself. Implementations of the three mechanisms are based on uIPv6 stack of Contiki OS. So far it works well on the platform of Cooja (an in-carried simulator of Contiki).

//////////////Instructions on Neighbor Discovery Configuration///////////////////////

What does it do
===============
These files, alongside some core modifications, add support for IPv6 Neighbor Discovery
to contiki's uIPv6.

Currently, three modes are supported:

* '6Lo-ND' (RFC6775)
* 'IPv6-ND' (RFC4861)    
* 'RPL-based ND' new protocol proposed by the author


Where to Start
==============
The best place in 
1.6Lo-ND:
`examples/6Lo-ND-host`,`examples/6Lo-ND-rt`;
2.IPv6-ND:
`examples/IPv6-ND-host`,`examples/IPv6-ND-rt`;
3. RPL-ND:
`examples/ipv6/rpl-ND-root`,`examples/ipv6/rpl-ND-clients`.

The examples combined with packet trace tools will demonstrate how these protocols behaves.

How to Use
==========
Look in `core/net/ipv6/multicast/uip-nd6-engines.h` for a list of supported
Neighbor Discovery engines.

To turn on neighbor discovery support, add this line in your `project-` or `contiki-conf.h`

        #define UIP_ND6_CONF_ENGINE xyz

  where xyz is a value from `uip-nd6-engines.h`

To disable:

        #define UIP_ND6_CONF_ENGINE 0

You also need to make sure the neighbor discovery code gets built. 


//////////Instructions on Neighbor Discovery Proxy Gateway Test////////////////

The implementation of 'RPL-based ND' also realize the ND proxy on the root node(see file of examples/ipv6/rpl-ND-root). It is aimed to run on a united simulation environment to test the functionality of the new protocol 'RPL-based ND'. The united simulation environment is constituted by three parts: 1. a core IPv6 network running on GNS3; 2. an 'RPL-based ND' installed 6LoWPAN network running on cooja connected with the core IPv6 network through a virtual network interface TAP0;  3. an VPCS running on GNS3 connected with the core IPv6 network. To test functionalities of the ND proxy gateway:

1. build up an IPv6 network on GNS3 made up of several IPv6 routers reconfigured with IPv6 Neighbor Discovery functions and IPv6 Routing functions as well as initializing each ethernet interfaces to be used;

2. create a 6LoWPAN network on cooja made up of nodes in the role of rpl-ND-root(examples/ipv6/rpl-ND-root) and rpl-ND-clients(examples/ipv6/rpl-ND-clients);

3. bind the rpl-ND-root node with a process listening on "127.0.0.1:60001" by using a mote tool "listen on serial(server)" provided by cooja;

4. run the tool of tunslip6 by the command "./tunslip6 -T -t tap0 -v5 -a 127.0.0.1 A/B", 'A' is the IPv6 address commissioned on the gateway's virtual network interface 'tap0', 'B' is the length of the prefix you set for the 6LoWPAN network. In this way, a virtual network interface tap0 will be installed connecting with the 6LoWPAN gateway's serial device through which packets will be delivered the gw's core uIPv6 network stack and be processed furtherly by the Neighbor Discovery proxy module. Note that the prefix of the 6LoWPAN must coincides with the IPv6 address area of its connected IPv6 router running on the GNS3; 

5. open a VPCS terminal, try to ping each node within the 6LoWPAN by command "ping xxxx", 'xxxx' is the IPv6 address auto-configured by the node itself. You will see echo replies are received successfully soon!


