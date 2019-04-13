/*
 * Copyright (C) 2015 NEC Europe Ltd. All rights reserved.
 * Author: Michio Honda
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <bsd_glue.h> /* from netmap-release */
#include <bsd_glue_opp.h>
#include <contrib/opp/opp_kern.h>

/* from FreeBSD in6.c */
/*
 * Convert IP6 address to printable (loggable) representation. Caller
 * has to make sure that ip6buf is at least INET6_ADDRSTRLEN long.
 */
static char digits[] = "0123456789abcdef";
char *
ip6_sprintf(char *ip6buf, const struct in6_addr *addr)
{
	int i, cnt = 0, maxcnt = 0, idx = 0, index = 0;
	char *cp;
	const u_int16_t *a = (const u_int16_t *)addr;
	const u_int8_t *d;
	int dcolon = 0, zero = 0;

	cp = ip6buf;

	for (i = 0; i < 8; i++) {
		if (*(a + i) == 0) {
			cnt++;
			if (cnt == 1)
				idx = i;
		}
		else if (maxcnt < cnt) {
			maxcnt = cnt;
			index = idx;
			cnt = 0;
		}
	}
	if (maxcnt < cnt) {
		maxcnt = cnt;
		index = idx;
	}

	for (i = 0; i < 8; i++) {
		if (dcolon == 1) {
			if (*a == 0) {
				if (i == 7)
					*cp++ = ':';
				a++;
				continue;
			} else
				dcolon = 2;
		}
		if (*a == 0) {
			if (dcolon == 0 && *(a + 1) == 0 && i == index) {
				if (i == 0)
					*cp++ = ':';
				*cp++ = ':';
				dcolon = 1;
			} else {
				*cp++ = '0';
				*cp++ = ':';
			}
			a++;
			continue;
		}
		d = (const u_char *)a;
		/* Try to eliminate leading zeros in printout like in :0001. */
		zero = 1;
		*cp = digits[*d >> 4];
		if (*cp != '0') {
			zero = 0;
			cp++;
		}
		*cp = digits[*d++ & 0xf];
		if (zero == 0 || (*cp != '0')) {
			zero = 0;
			cp++;
		}
		*cp = digits[*d >> 4];
		if (zero == 0 || (*cp != '0')) {
			zero = 0;
			cp++;
		}
		*cp++ = digits[*d & 0xf];
		*cp++ = ':';
		a++;
	}
	*--cp = '\0';
	return (ip6buf);
}

static int linux_opp_init(void)
{
	return -opp_init();
}

static void linux_opp_fini(void)
{
	opp_fini();
}

void *
opp_os_malloc(size_t size)
{
	        return kmalloc(size, GFP_ATOMIC | __GFP_ZERO);
}

void
opp_os_free(void *addr)
{
	kfree(addr);
}

void *
opp_os_vmalloc(size_t size)
{
	return vmalloc(size);
}

void
opp_os_vfree(void *addr)
{
	vfree(addr);
}

module_init(linux_opp_init);
module_exit(linux_opp_fini);
MODULE_AUTHOR("Michio Honda");
MODULE_DESCRIPTION("OPP: Open Packet Processor");
MODULE_LICENSE("Dual BSD/GPL");
