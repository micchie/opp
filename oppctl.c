/*
 *  BSD LICENSE
 *
 * Copyright(c) 2015 NEC Europe Ltd. All rights reserved.
 *  All rights reserved.
 * Author: Michio Honda
 *
 * Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *    * Neither the name of NEC Europe Ltd. nor the names of
 *      its contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/opp.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef linux
#include <bsd/string.h>
#endif

int
main(int argc, char **argv)
{
	struct nm_desc *nmd;
	struct oppreq oreq;
	int f;
	char name[16];

	if (argc != 7) {
		fprintf(stdout,
		  "usage: oppctl [1,2] srcaddr srcport dstaddr dstport [udp,tcp] (1 for addtion, 2 for deletion)\n");
		return 0;
	}

	snprintf(name, sizeof(name), "%svi0", OPP_BDG_NAME);
	bzero(&oreq, sizeof(oreq));
	strlcpy(oreq.or_name, name, sizeof(oreq.or_name));

	oreq.or_cmd = atoi(argv[1]);
	f = index(argv[2], ':') ? AF_INET6 : index(argv[2], '.') ? AF_INET : -1;
	if (f < 0) {
		fprintf(stderr, "unknown address family\n");
		return 0;
	}
	oreq.or_family = f;
	if (1 != inet_pton(f, argv[2], &oreq.or_src4.sin_addr)) {
		perror("inet_pton");
		return 0;
	}
	oreq.or_src4.sin_port = htons(atoi(argv[3]));
	if (1 != inet_pton(f, argv[4], &oreq.or_dst4.sin_addr)) {
		perror("inet_pton");
		return 0;
	}
	oreq.or_dst4.sin_port = htons(atoi(argv[5]));
	oreq.or_transport = !strcmp(argv[6], "tcp") ? IPPROTO_TCP : 
		(!strcmp(argv[6], "udp") ?  IPPROTO_UDP : 0);
	if (!oreq.or_transport) {
		fprintf(stderr, "Unknown transport\n");
		return 0;
	}

	nmd = nm_open(name, NULL, 0, NULL);
	if (nmd == NULL) {
		D("Unable to open %s", name);
	}

	if (ioctl(nmd->fd, NIOCCONFIG, &oreq)) {
		perror("ioctl");
	}
	return 0;
}
