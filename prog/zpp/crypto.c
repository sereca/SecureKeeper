/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors: Stefan Brenner, Colin Wulf
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "crypto.h"
#include "utils.h"
#include "Enclave.h"

#include "debugflag.h"

const sgx_aes_gcm_128bit_key_t aes_key[16] = { 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b',
		'c', 'd' };
const uint8_t aes_iv[12] = { 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd' };
/**
 * This function returns the overhead of the encryption including the nonce
 **/
int get_overhead_with_nonce() {
	// HMAC + path hash
	return MACLEN + IVLEN + HASHLEN;
}

int printSgxStatus(char* fname, sgx_status_t status) {
	switch (status) {
	case SGX_SUCCESS:
#ifdef DEBUG            
		printf("sgx function '%s' returned: SGX_SUCCESS.\n", fname);
#endif
		break;
	case SGX_ERROR_INVALID_PARAMETER:
		printf("sgx function '%s' returned: SGX_ERROR_INVALID_PARAMETER.\n", fname);
		break;
	case SGX_ERROR_OUT_OF_MEMORY:
		printf("sgx function '%s' returned: SGX_ERROR_OUT_OF_MEMORY.\n", fname);
		return 1;
//		break;
	case SGX_ERROR_UNEXPECTED:
		printf("sgx function '%s' returned: SGX_ERROR_UNEXPECTED.\n", fname);
		break;
	case SGX_ERROR_MAC_MISMATCH:
		printf("sgx function '%s' returned: SGX_ERROR_MAC_MISMATCH.\n", fname);
		break;
	default:
		printf("sgx function '%s' returned: Unknown status code (%X).\n", fname, (int) status);
	}
	return 0;
}

char* sgx_encrypt_rijndael(char* plain, size_t* ret_size) {
	size_t size = *ret_size;

	if (size <= 0) {
		printf("buffer len invalid, %d.\n", size);
		return NULL;
	}

	uint8_t* cipher = (uint8_t*) malloc(size + MACLEN);
#ifdef MMGT
	printf("%s:%s:%d: %p = malloc(%d).\n", __FILE__, __FUNCTION__, __LINE__, cipher, size + MACLEN);
#endif
	uint8_t macbuffer[MACLEN];

	sgx_status_t status = sgx_rijndael128GCM_encrypt(aes_key, plain, size, cipher, aes_iv, IVLEN, NULL, 0, &macbuffer);

	memcpy(cipher + size, macbuffer, MACLEN);
	*ret_size = size + MACLEN;

	if (printSgxStatus("sgx_rijndael128GCM_encrypt in sgx_encrypt_rijndael",status) == 1) {
		printf("%s:%s:%d: out of memory, size: %d.\n", __FILE__, __FUNCTION__, __LINE__, size);
	}

	return cipher;
}

char* sgx_decrypt_rijndael(char* cipher, size_t* ret_size) {
	size_t size = *ret_size;

	if (size <= 0) {
		printf("%s:%s:%d: size out of bounds, %d.\n", __FILE__, __FUNCTION__, __LINE__, size);
		return 0;
	}

	uint8_t macbuffer[MACLEN];
	char* mac_pos = cipher + size - MACLEN;
	memcpy(macbuffer, mac_pos, MACLEN);
	size -= MACLEN;

	if (size <= 0) {
		printf("%s:%s:%d: cipher len invalid, %d.\n", __FILE__, __FUNCTION__, __LINE__, size);
		return NULL;
	}

	uint8_t* plain = (uint8_t*) malloc(size);
#ifdef MMGT
	printf("%s:%s:%d: %p = malloc(%d).\n", __FILE__, __FUNCTION__, __LINE__, plain, size);
#endif

	sgx_status_t status = sgx_rijndael128GCM_decrypt(aes_key, cipher, size, plain, aes_iv, IVLEN, NULL, 0,
			(const sgx_aes_gcm_128bit_tag_t*) &macbuffer);

	if (printSgxStatus("sgx_rijndael128GCM_decrypt in sgx_decrypt_rijndael",status) == 1) {
		printf("%s:%s:%d: out of memory, size: %d.\n", __FILE__, __FUNCTION__, __LINE__, size);
	}

	*ret_size = size;

	return plain;
}

/**
 * This functions encrypts a buffer of a certain size. 
 * The incoming buffer, stored in p_package->buffer is freed and replaced by the encrypted buffer, stored in p_package->buffer
 * The incoming size of the buffer, stored in p_package->size is exchanged for the new size.
 * Returns 0 on success
 **/

int encrypt_buffer(package_t * p_package) {
#ifdef DEBUG
	printf("encrypt payload.\n");
#endif

	// (!) encrypt call changes the p_package->size, adding MAC (!)
	char* cipher = sgx_encrypt_rijndael(p_package->buffer, &(p_package->size));
#ifdef MMGT
	printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, p_package->buffer);
#endif
	free(p_package->buffer);
	p_package->buffer = cipher;

	return 0;
}

/**
 * This functions decrypts a buffer of a certain size. 
 * The incoming buffer, stored in p_package->buffer is freed and replaced by the decrypted buffer, stored in p_package->buffer
 * The incoming size of the buffer, stored in p_package->size is exchanged for the new size.
 * Returns 0 on success
 **/
int decrypt_buffer(package_t * p_package) {
#ifdef DEBUG
	printf("decrypt payload.\n");
#endif

	// (!) decrypt call changes the p_package->size, removing MAC (!)
	char* plain = sgx_decrypt_rijndael(p_package->buffer, &(p_package->size));
#ifdef MMGT
	printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, p_package->buffer);
#endif
	free(p_package->buffer);
	p_package->buffer = plain;

	return 0;
}

/**
 * This functions decrypt the metadata of a node,
 * it decreases the dataLength stated
 **/
void decrypt_metadata(struct Stat * stat) {
	if (stat->dataLength > get_overhead_with_nonce()) {
		stat->dataLength -= get_overhead_with_nonce();
	}
}

/**
 * This function encrypts the payload, if it the encrypt type is NORMAL.
 * Returns 0 on success, -1 otherwise.
 **/
int encrypt_payload(char ** p_buffer, int * p_size, char * path) {
	int rc = -1, plen = 0, newsize = 0;
	char * newbuffer;
	sgx_sha256_hash_t * pathHash;

	// check path length
	plen = strlen(path);
	if(plen < 0 || plen > 256) {
		printf("WARN: unexpected path length: %d.\n", plen);
	}

	// calc. path hash
//	hexdump("CRE: hash of", path, strlen(path));
	pathHash = (sgx_sha256_hash_t*) malloc(HASHLEN);
	sgx_sha256_msg(path, plen, pathHash);
//	hexdump("CRE: hash", pathHash, HASHLEN);

	// new payload size
	if(*p_size > 0) {
		newsize = *p_size + HASHLEN;
	} else {
		newsize = HASHLEN;
	}

	// new payload buffer
	newbuffer = (char*) malloc(newsize);
#ifdef MMGT
	printf("%s:%s:%d: %p = malloc(%d).\n", __FILE__, __FUNCTION__, __LINE__, newbuffer, newsize);
#endif
	if(*p_size > 0) {
		memcpy(newbuffer, *p_buffer, *p_size);
#ifdef MMGT
	printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, *p_buffer);
#endif
		free(*p_buffer);
		memcpy(newbuffer + *p_size, pathHash, HASHLEN);
	} else {
		memcpy(newbuffer, pathHash, HASHLEN);
	}

	free(pathHash);

	package_t package = { newbuffer, newsize };

	rc = encrypt_buffer(&package);

	*p_buffer = package.buffer;
	*p_size = package.size;

	return 1; // always changed payload, because hash(path)
}

/**
 * This function decrypts the payload.
 * Returns 0 on success, -1 otherwise.
 **/
int decrypt_payload(char ** p_buffer, int * p_size, char * pathHash) {
	int rc = -1, cmp = 1;
	package_t package = { *p_buffer, *p_size };

	if (*p_size > 0)
			rc = decrypt_buffer(&package);

	// message layout: payload, mac, hash(plainpath)
	// pathHash = hash(plainpath) from list
	cmp = memcmp(pathHash, package.buffer + package.size - HASHLEN, HASHLEN);
	if(cmp != 0) {
		printf("ERROR: path hash invalid (%d), this is (kind of) fine for sequential nodes.\n", cmp);
//		hexdump("list Hash", pathHash, HASHLEN);
//		hexdump("pyl  Hash", package.buffer + package.size - HASHLEN, HASHLEN);
	} else {
#ifdef DEBUG
		printf("INFO: path hash correct.\n");
#endif
	}

	*p_buffer = package.buffer;
	*p_size = package.size - HASHLEN;

	return rc;
}

void encrypt_path(char** path) {
	char *ret_path;
	size_t ret_len;
	if (path_encryption(*path, strlen(*path), &ret_path, &ret_len)) {
		printf("error during path encryption.\n");
	}
#ifdef DEBUG
	printf("Encrypt path: %s -> %s.\n", *path, ret_path);
#endif
#ifdef MMGT
	printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, *path);
#endif
	free(*path);
	*path = ret_path;
}

void decrypt_path(char** cipherpath) {
	char *ret_cipherpath;
	size_t ret_len;
	if (path_decryption(*cipherpath, strlen(*cipherpath), &ret_cipherpath, &ret_len)) {
		printf("error during cipherpath decryption.\n");
	} else {
#ifdef DEBUG
		printf("Decrypt path: %s -> %s.\n", *cipherpath, ret_cipherpath);
#endif
#ifdef MMGT
		printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, *cipherpath);
#endif
		free(*cipherpath);
		*cipherpath = ret_cipherpath;
	}
}

// chunk + hmac + iv -> decrypted(chunk) 
char* decrypt_chunk(const char* chunk, size_t* length) {
	// decode
	size_t decoded_len = base64url_decode_len(*length);

	if(decoded_len < 0 || decoded_len > 2*1024*1024) {
		printf("%s:%s:%d: decoded_len < 0 (%d (%d)).\n", __FILE__, __FUNCTION__, __LINE__, decoded_len, *length);
	}

	if (decoded_len < MACLEN + IVLEN) {
		printf("%s:%s:%d: decoded_len < %d + %d: %lu.\n", __FILE__, __FUNCTION__, __LINE__, MACLEN, IVLEN, decoded_len);
		*length = strlen(chunk);
		char* plain = malloc(*length + 1);
		memcpy(plain, chunk, *length);
		return plain;
	}

	char* decoded = (char*) malloc(decoded_len);
#ifdef MMGT
	printf("%s:%s:%d: %p = malloc(%d).\n", __FILE__, __FUNCTION__, __LINE__, decoded, decoded_len);
#endif
	base64url_decode(chunk, *length, decoded, &decoded_len);

	*length = decoded_len - MACLEN - IVLEN;

	const uint8_t* iv = decoded + decoded_len - IVLEN;

	// decrypt
	char* plain = malloc(*length + 1);
#ifdef MMGT
	printf("%s:%s:%d: %p = malloc(%d).\n", __FILE__, __FUNCTION__, __LINE__, plain, sizeof(*length + 1));
#endif
	const sgx_aes_gcm_128bit_tag_t* mac = (const sgx_aes_gcm_128bit_tag_t*) (decoded + *length);
//	hexdump("mac", mac, MACLEN);
	sgx_status_t ret = sgx_rijndael128GCM_decrypt(aes_key,		// key
			decoded,		// cipher input
			*length,		// cipher input length
			plain, 			// plain output
			iv,				// AES IV
			IVLEN, 			// AES IV length
			NULL,			// AAD
			0, 				// AAD length
			mac 			// HMAC buffer
			);
	if(ret != SGX_SUCCESS)
		printSgxStatus("sgx_rijndael128GCM_decrypt in decrypt_chunk", ret);
	plain[*length] = '\0';
#ifdef MMGT
	printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, decoded);
#endif
	free(decoded);

	return plain;
}

int path_decryption(const char* cipher_path, const size_t cipher_path_len, char** ret_path, size_t* ret_len) {
	char *decrypted, *plain;
	int index = 1, i, out_index = 1;
	size_t length, dec_len, plain_len = 0;

	if (strlen(cipher_path) == 1) {
		*ret_path = malloc(2);
#ifdef MMGT
		printf("%s:%s:%d: %p = malloc(%d).\n", __FILE__, __FUNCTION__, __LINE__, *ret_path, 2);
#endif
		memcpy(*ret_path, cipher_path, 2);
		*ret_len = cipher_path_len;
		return 0;
	}

	// calculate plain path length
	for (i = 1; i <= cipher_path_len; i++) {
		if (cipher_path[i] == '/' || cipher_path[i] == '\0') {
			length = i - index;
			plain_len += 1 + base64url_decode_len(length) - 16 - 12;
			if (plain_len > 8192) {
				printf("plain_len > 8192: %lu/%d.\n", plain_len, plain_len);
				if ((int) plain_len == -24) {
					printf("  probably node exists.\n");
				}
				return 1;
			}
			index = i + 1; // skip slash
		}
	}

	plain = (char*) malloc(plain_len + 1);
#ifdef MMGT
	printf("%s:%s:%d: %p = malloc(%d).\n", __FILE__, __FUNCTION__, __LINE__, plain, plain_len + 1);
#endif
	memset(plain, '/', plain_len);
	plain[plain_len] = '\0';

	index = 1;
	for (i = 1; i <= cipher_path_len; i++) {
		if (cipher_path[i] == '/' || cipher_path[i] == '\0') {
			length = i - index;
			dec_len = length;

			// hexdump("chunk", start, length);
			decrypted = decrypt_chunk(cipher_path + index, &dec_len);
			// hexdump("decrypted", decrypted, dec_len);
			// printf("memcpy(%p + %d, %p, %d);", plain, index, decrypted, dec_len);
			memcpy(plain + out_index, decrypted, dec_len);
#ifdef MMGT
			printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, decrypted);
#endif
			free(decrypted);
			out_index += dec_len + 1;
			// hexdump("path", plain, plain_len);
			index = i + 1; // skip slash
		}
	}

	// hexdump("decrypted path", plain, plain_len);
	*ret_path = plain;
	*ret_len = plain_len + 1;
	return 0;
}

// chunk -> encrypted(chunk) + hmac + iv
char* encrypt_chunk(const char* chunk, size_t* clen, const char* fullpath, const size_t fplen) {
	char* cipherchunk = (char*) malloc(*clen + 16 + 12);
#ifdef MMGT
	printf("%s:%s:%d: %p = malloc(%d).\n", __FILE__, __FUNCTION__, __LINE__, cipherchunk, *clen + 16 + 12);
#endif
	uint8_t macbuffer[MACLEN];

	sgx_sha256_hash_t* iv = malloc(HASHLEN);
#ifdef MMGT
	printf("%s:%s:%d: %p = malloc(%d).\n", __FILE__, __FUNCTION__, __LINE__, iv, HASHLEN);
#endif
	//TODO: improvement: insert 'salt' into hash
	sgx_sha256_msg(fullpath, fplen, iv);
#ifdef DEBUG
	 hexdump("Using hash of", fullpath, fplen);
	 printf("  for %s (%d).\n", chunk, *clen);
#endif

	// encrypt chunk
	sgx_rijndael128GCM_encrypt(aes_key, chunk,			// plaintext
			*clen,			// plaintext length
			cipherchunk,	// ciphertext
			(const uint8_t*) iv,// AES IV
			IVLEN,				// AES IV length
			NULL,			// AAD
			0,				// AAD length
			&macbuffer		// HMAC buffer
			);

	// copy mac 
	memcpy(cipherchunk + *clen, &macbuffer, MACLEN);
	// copy iv
	memcpy(cipherchunk + *clen + MACLEN, iv, IVLEN);

	// encode base64url
	size_t elen = base64url_encode_len(*clen + MACLEN + IVLEN);
	char* cipherchunkencoded = malloc(elen);
	base64url_encode(cipherchunk, *clen + MACLEN + IVLEN, cipherchunkencoded, &elen);
	*clen = elen;
#ifdef MMGT
	printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, iv);
#endif
	free(iv);
#ifdef MMGT
	printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, cipherchunk);
#endif
	free(cipherchunk);

	return cipherchunkencoded;
}

int path_encryption(const char* path, const size_t path_len, char** ret_path, size_t* ret_len) {
	size_t clen, cipher_path_len = 0, token_len, length;
	int slashes = 0, offset, index = 1, i, token_b64_len;
	char *tmp, *ptr, *cipher_path, *token, *encrypted_chunk;

	if (strlen(path) == 1) {
		*ret_path = malloc(2);
#ifdef MMGT
		printf("%s:%s:%d: %p = malloc(%d).\n", __FILE__, __FUNCTION__, __LINE__, *ret_path, 2);
#endif
		memcpy(*ret_path, path, 2);
		*ret_len = path_len;
		return 0;
	}

	// calculate cipher path length
	for (i = 1; i <= path_len; i++) {
		if (path[i] == '/' || path[i] == '\0') {
			length = i - index;
			token_b64_len = base64url_encode_len(length + 16 + 12);
			cipher_path_len += 1 + token_b64_len;
			index = i + 1; // skip slash
		}
	}

	// encrypt the path chunk by chunk
	cipher_path = (char*) malloc(cipher_path_len + 1);
#ifdef MMGT
	printf("%s:%s:%d: %p = malloc(%d).\n", __FILE__, __FUNCTION__, __LINE__, cipher_path, cipher_path_len + 1);
#endif
	memset(cipher_path, '/', cipher_path_len);
	cipher_path[cipher_path_len] = '\0';
	*ret_path = cipher_path;
	*ret_len = cipher_path_len;
	offset = 1;
	index = 1;
	for (i = 1; i <= path_len; i++) {
		if (path[i] == '/' || path[i] == '\0') {
			length = i - index;
			// encrypt path chunk (+16B length)
			encrypted_chunk = encrypt_chunk(path + index, &length, path, i);

			// add chunk to resulting cipher path
			memcpy(cipher_path + offset, encrypted_chunk, length);
#ifdef MMGT
			printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, encrypted_chunk);
#endif
			free(encrypted_chunk);

			offset += length;
			// If not yet at end, add space for a slash
			if (path[i] == '/') {
				offset++;
			}

			if (offset > cipher_path_len) {
				printf("cipher path longer than expected.\n");
				return -1;
			}

			index = i + 1;
		}
	}

	return 0;
}
