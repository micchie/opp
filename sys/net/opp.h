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

#if defined(linux) && defined(__KERNEL__)
#include <linux/in.h>
#else
#include <netinet/in.h>
#endif

#define OPP_BDG_NAME	"valeo:"
#define OPP_ADD		1
#define OPP_DEL		2

struct opp_flow {
	struct ether_header ether;
	union { 
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr sa;
	} src;
	union { 
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr sa;
	} dst;
	uint8_t protocol;
};

struct oppreq {
	char or_name[IFNAMSIZ];
	union {
		struct opp_flow or_flow;
	} or_ifru;
	int or_cmd;
};

#define or_src4	or_ifru.or_flow.src.sin
#define or_src6	or_ifru.or_flow.src.sin6
#define or_dst4	or_ifru.or_flow.dst.sin
#define or_dst6	or_ifru.or_flow.dst.sin6
#define or_family or_ifru.or_flow.src.sa.sa_family
#define or_transport or_ifru.or_flow.protocol
