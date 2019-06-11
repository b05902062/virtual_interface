all:
	gcc virtual_interface.c construct_dhcp_packet.c dhcp_protocol.c -o virtual_interface
	gcc personas_pipe.c -o personas
bad: badguy.c construct_dhcp_packet.c dhcp_protocol.c
	gcc badguy.c construct_dhcp_packet.c dhcp_protocol.c -o bad

virt: virtual_interface.c construct_dhcp_packet.c dhcp_protocol.c
	gcc virtual_interface.c construct_dhcp_packet.c dhcp_protocol.c -o virt
