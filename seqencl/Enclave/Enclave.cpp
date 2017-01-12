/**
*   Copyright(C) 2011-2015 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   *Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include "utils.h"
#include "crypto.h"

#include "debugflag.h"

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print(buf);
}

int ecall_get_sequential_path(char* path, size_t path_len, size_t buffer_size, int eid)
{
#if defined(ENCLAVE_TRANSITION) || defined(DEMO)
	printf("\nSEQ ENCLAVE(ID=%d) START: path len %d.\n", eid, path_len);
#endif
#ifdef DEBUG
	hexdump("ENCL: path hexdump", path, path_len);
	printf("ENCL: path_len=%d.\n", path_len);
#endif
	path_len -= 10;

	// we decrypt the given path, skipping 10 bytes in the end that contain the seq.no.
	char * plainpath;
	size_t ret_len;
	int ret = path_decryption(path, path_len, &plainpath, &ret_len); // malloc
#ifdef DEBUG
	printf("ret of path decryption is %d.\n", ret);
	hexdump("ENCL: decrypted path", plainpath, ret_len);
#endif

	// make room for 10 Bytes seq.no in decrypted path
	plainpath = (char*)realloc(plainpath, ret_len + 10);
	// copy seqno to path
	memcpy(plainpath+ret_len-1,path+path_len,10);
	ret_len += 10;
	// \0 terminate the string
	plainpath[ret_len-1] = '\0';

#ifdef DEBUG
	hexdump("plainpath + seq", plainpath, ret_len);
#endif

	// encrypt the plain path and seq.no.
	char * cipherpath;
	size_t ret_len2;
#if defined(ENCLAVE_TRANSITION) || defined(DEMO)
	printf("Encrypting plain path and sequence number...\n");
#endif
	int ret2 = path_encryption(plainpath, ret_len-1, &cipherpath, &ret_len2); // malloc
#ifdef DEBUG
	printf("ret2 of path encryption is %d.\n", ret2);
	hexdump("ENCL: again encrypted path", cipherpath, ret_len2);
#endif

	// return final result
	memcpy(path, cipherpath, ret_len2);

/* the following block is only testing */
//	char * plainpath2;
//	size_t ret_len3;
//	int ret3 = path_decryption(cipherpath, ret_len2, &plainpath2, &ret_len3);
//#ifdef DEBUG
//	printf("ret3 of path decryption is %d.\n", ret3);
//	hexdump("ENCL: again decrypted path", plainpath2, ret_len3);
//#endif

	free(plainpath);
	free(cipherpath);
//	free(plainpath2);

	// return the length of the final result
#if defined(ENCLAVE_TRANSITION) || defined(DEMO)
	printf("SEQ ENCLAVE END: result size %d.\n\n", ret_len2);
#endif
	return (int)ret_len2;
}
