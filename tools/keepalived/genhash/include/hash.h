/*
 * Soft:        Perform a GET query to a remote HTTP/HTTPS server.
 *              Set a timer to compute global remote server response
 *              time.
 *
 * Part:        Hash-related declarations (to break circular deps).
 *
 * Authors:     Jan Pokorny, <jpokorny@redhat.com>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright 2013 Red Hat, Inc.
 * Copyright (C) 2014-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _HASH_H
#define _HASH_H

/* system includes */
#include <openssl/evp.h>
#include <openssl/md5.h>	/* for MD5_DIGEST_LENGTH (not deprecated) */
#ifdef _WITH_SHA1_
#include <openssl/sha.h>	/* for SHA_DIGEST_LENGTH (not deprecated) */
#endif

/* available hashes enumeration */
enum feat_hashes {
	hash_first,
	hash_md5 = hash_first,
#ifdef _WITH_SHA1_
	hash_sha1,
#endif
	hash_guard,
	hash_default = hash_md5,
};

typedef struct {
	/* OpenSSL 3.0 deprecates the legacy MD5/SHA1 one-shot APIs; use a single
	   EVP context. Allocated by the init wrapper, freed by the final wrapper
	   (or by HASH_CLEANUP on the error path). */
	EVP_MD_CTX		*ctx;
} hash_context_t;

typedef int (*hash_init_f)(hash_context_t *);
typedef int (*hash_update_f)(hash_context_t *, const void *, unsigned long);
typedef int (*hash_final_f)(unsigned char *, hash_context_t *);

typedef struct {
	hash_init_f		init;
	hash_update_f		update;
	hash_final_f		final;
	unsigned char		length;		/* length of the digest */
	const char		*id;		/* command-line handing + help */
	const char		*label;		/* final output */
} hash_t;

#endif
