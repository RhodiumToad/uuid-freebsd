/*-------------------------------------------------------------------------
 *
 * UUID generation functions for FreeBSD
 *
 * Copyright (c) 2009 Andrew Gierth
 *
 * Some parts originated from contrib/uuid-ossp, which is
 * Copyright (c) 2007-2008 PostgreSQL Global Development Group
 *
 * Permission to use, copy, modify, and distribute this software for
 * any purpose with or without fee is hereby granted, provided that
 * the above copyright notice and this permission notice appear in all
 * copies.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "utils/uuid.h"

/* OS has a uuid_hash that conflicts with ours; kill it*/
/* explicit path since we do _not_ want to get any other version */
#define uuid_hash freebsd_uuid_hash
#include "/usr/include/uuid.h"
#undef uuid_hash

#include <md5.h>
#include <sha.h>

PG_MODULE_MAGIC;

Datum uuid_nil(PG_FUNCTION_ARGS);
Datum uuid_ns_dns(PG_FUNCTION_ARGS);
Datum uuid_ns_url(PG_FUNCTION_ARGS);
Datum uuid_ns_oid(PG_FUNCTION_ARGS);
Datum uuid_ns_x500(PG_FUNCTION_ARGS);

Datum uuid_generate_v1(PG_FUNCTION_ARGS);
Datum uuid_generate_v1mc(PG_FUNCTION_ARGS);
Datum uuid_generate_v3(PG_FUNCTION_ARGS);
Datum uuid_generate_v4(PG_FUNCTION_ARGS);
Datum uuid_generate_v5(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(uuid_nil);
PG_FUNCTION_INFO_V1(uuid_ns_dns);
PG_FUNCTION_INFO_V1(uuid_ns_url);
PG_FUNCTION_INFO_V1(uuid_ns_oid);
PG_FUNCTION_INFO_V1(uuid_ns_x500);

PG_FUNCTION_INFO_V1(uuid_generate_v1);
PG_FUNCTION_INFO_V1(uuid_generate_v1mc);
PG_FUNCTION_INFO_V1(uuid_generate_v3);
PG_FUNCTION_INFO_V1(uuid_generate_v4);
PG_FUNCTION_INFO_V1(uuid_generate_v5);

/* we assume that the string representation is portable and that the
 * native binary representation might not be. But for *ns, we assume
 * that pg's internal storage of uuids is the simple byte-oriented
 * binary format. */

static Datum
internal_uuid_create(int v, unsigned char *ns, char *ptr, int len)
{
	char strbuf[40];

	switch (v)
	{
		case 0:	 /* constant-value uuids: nil, or namespace uuids */
			strlcpy(strbuf, ptr, 37);
			break;

		case 4: default:   /* random uuid */
		{
			sprintf(strbuf, "%08lx-%04x-%04x-%04x-%04x%08lx",
					(unsigned long) arc4random(),
					(unsigned) (arc4random() & 0xffff),
					(unsigned) ((arc4random() & 0xfff) | 0x4000),
					(unsigned) ((arc4random() & 0x3fff) | 0x8000),
					(unsigned) (arc4random() & 0xffff),
					(unsigned long) arc4random());
			break;
		}
			
		case 1:	 /* time/node-based uuids */
		{
			uuid_t uu;
			uint32_t status = uuid_s_ok;
			char *str = NULL;

			uuid_create(&uu, &status);

			if (status == uuid_s_ok)
			{
				uuid_to_string(&uu, &str, &status);
				if (status == uuid_s_ok)
				{
					strlcpy(strbuf, str, 37);

					/* PTR, if set, replaces the trailing characters of the uuid;
					 * this is to support v1mc, where a random multicast MAC is
					 * used instead of the physical one
					 */
					
					if (ptr && len <= 36)
						strcpy(strbuf + (36 - len), ptr);
				}
				if (str)
					free(str);
			}

			if (status != uuid_s_ok)
			{
				ereport(ERROR,
						(errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
						 errmsg("FreeBSD uuid library failure: %d", (int) status)));
			}
			
			break;
		}

		case 3:	 /* namespace-based MD5 uuids */
		{
			/* we could use pg's md5(), but we're already pulling in libmd */
			MD5_CTX ctx;
			unsigned char buf[16];

			MD5Init(&ctx);
			MD5Update(&ctx, ns, 16);
			MD5Update(&ctx, (unsigned char *)ptr, len);
			MD5Final(buf, &ctx);

			sprintf(strbuf,
					"%02x%02x%02x%02x-"
					"%02x%02x-%02x%02x-%02x%02x-"
					"%02x%02x%02x%02x%02x%02x",
					buf[0], buf[1], buf[2], buf[3],
					buf[4], buf[5], ((buf[6] & 0xf) | 0x30), buf[7],
					((buf[8] & 0x3F) | 0x80), buf[9], buf[10], buf[11],
					buf[12], buf[13], buf[14], buf[15]);

			break;
		}

		case 5:	 /* namespace-based SHA1 uuids */
		{
			SHA_CTX ctx;
			unsigned char buf[20];

			SHA1_Init(&ctx);
			SHA1_Update(&ctx, ns, 16);
			SHA1_Update(&ctx, (unsigned char *)ptr, len);
			SHA1_Final(buf, &ctx);

			sprintf(strbuf,
					"%02x%02x%02x%02x-"
					"%02x%02x-%02x%02x-%02x%02x-"
					"%02x%02x%02x%02x%02x%02x",
					buf[0], buf[1], buf[2], buf[3],
					buf[4], buf[5], ((buf[6] & 0xf) | 0x50), buf[7],
					((buf[8] & 0x3F) | 0x80), buf[9], buf[10], buf[11],
					buf[12], buf[13], buf[14], buf[15]);

			break;
		}
	}

	return DirectFunctionCall1(uuid_in, CStringGetDatum(strbuf));
}

Datum
uuid_nil(PG_FUNCTION_ARGS)
{
	return internal_uuid_create(0, NULL, "00000000-0000-0000-0000-000000000000", 36);
}

Datum
uuid_ns_dns(PG_FUNCTION_ARGS)
{
	return internal_uuid_create(0, NULL, "6ba7b810-9dad-11d1-80b4-00c04fd430c8", 36);
}

Datum
uuid_ns_url(PG_FUNCTION_ARGS)
{
	return internal_uuid_create(0, NULL, "6ba7b811-9dad-11d1-80b4-00c04fd430c8", 36);
}

Datum
uuid_ns_oid(PG_FUNCTION_ARGS)
{
	return internal_uuid_create(0, NULL, "6ba7b812-9dad-11d1-80b4-00c04fd430c8", 36);
}

Datum
uuid_ns_x500(PG_FUNCTION_ARGS)
{
	return internal_uuid_create(0, NULL, "6ba7b814-9dad-11d1-80b4-00c04fd430c8", 36);
}

Datum
uuid_generate_v1(PG_FUNCTION_ARGS)
{
	return internal_uuid_create(1, NULL, NULL, 0);
}

Datum
uuid_generate_v1mc(PG_FUNCTION_ARGS)
{
	char buf[20];

	sprintf(buf, "-%04x-%04x%08lx",
			(unsigned)((arc4random() & 0x3FFF) | 0x8000),
			/* set IEEE802 multicast and local-admin bits */
			(unsigned)((arc4random() & 0xffff) | 0x0300),
			(unsigned long) arc4random());
			
	return internal_uuid_create(1, NULL, buf, 18);
}

Datum
uuid_generate_v3(PG_FUNCTION_ARGS)
{
	pg_uuid_t  *ns = PG_GETARG_UUID_P(0);
	text	   *name = PG_GETARG_TEXT_P(1);

	return internal_uuid_create(3, (unsigned char *)ns,
								VARDATA(name), VARSIZE(name) - VARHDRSZ);
}

Datum
uuid_generate_v4(PG_FUNCTION_ARGS)
{
	return internal_uuid_create(4, NULL, NULL, 0);
}

Datum
uuid_generate_v5(PG_FUNCTION_ARGS)
{
	pg_uuid_t  *ns = PG_GETARG_UUID_P(0);
	text	   *name = PG_GETARG_TEXT_P(1);

	return internal_uuid_create(5, (unsigned char *)ns,
								VARDATA(name), VARSIZE(name) - VARHDRSZ);
}
