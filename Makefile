all:
	gcc getip_fprintf.c construct_packet.c -o getip
	gcc personas_pipe.c -o personas
