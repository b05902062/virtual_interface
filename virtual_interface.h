#ifndef VIRTUAL_INTERFACE_H
#define VIRTUAL_INTERFACE_H

#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>

extern char interface[IFNAMSIZ];
static void send_fd(char*s);

#endif
