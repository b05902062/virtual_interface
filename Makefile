all:
	gcc virtual_interface.c construct_dhcp_packet.c dhcp_protocol.c -o virtual_interface
	gcc personas_pipe.c -o personas
