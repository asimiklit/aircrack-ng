/*
* sha1-git.h
*
* This code is based on the GIT SHA1 Implementation.
*
* Copyright (C) 2009 Linus Torvalds <torvalds@linux-foundation.org>
* Copyright (C) 2009 Nicolas Pitre <nico@cam.org>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
* MA 02110-1301, USA.
*
*/

/*
* SHA1 routine optimized to do word accesses rather than byte accesses,
* and to avoid unnecessary copies into the context array.
*
* This was initially based on the Mozilla SHA1 implementation, although
* none of the original Mozilla code remains.
*/

typedef struct {
   unsigned int h0, h1, h2, h3, h4;
} SHA_CTX6420;

void SHA1_Init_64(SHA_CTX6420 *ctx, const void * data64byte);
void SHA1_Final_20(unsigned char ohash[20], const SHA_CTX6420 *ctx, const void * data20byte);
/***
* @ The 'datasize' must be less than 56. Just 1-55 byte of data is acceptable
****/
void SHA1_Final_l56(unsigned char ohash[20], const SHA_CTX6420 *ctx, const void * data, size_t datasize);
void SHA1_Assign_6420(SHA_CTX6420 *left, const SHA_CTX6420 *right);
/***
* @ The 'keysize' must be less than 65. Just 1-64 byte of data is acceptable
* @ The ipad and opad should not be initialized it just memory for ipad and opad
****/
void HMAC_SHA1_6420(const char* key, size_t keysize, const char* data, size_t datasize, unsigned char outkey[20]);
void HMAC_SHA1_6420v2(const char* key, size_t keysize, const char* data, size_t datasize, unsigned char outkey[20], SHA_CTX6420 * outkey_ipad, SHA_CTX6420 * outkey_opad);
void HMAC_SHA1_6420Ex(const SHA_CTX6420 * key_ipad, const SHA_CTX6420 * key_opad, const char* data, size_t datasize, unsigned char outkey[20]);

#define SHA_DIGEST_LENGTH 20
