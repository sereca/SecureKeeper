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
/**
 * These functions deal with the bytes coming from the connected zookeeper.
 * They always deserialize, decode and serialize data.
 **/

#include <stdlib.h>
#include <string.h>

#include "responseHandler.h"
#include "crypto.h"
#include "operationCodes.h"
#include "zookeeper.jute.h"
#include "errorCodes.h"
#include "list.h"
#include "utils.h"
#include "Enclave.h"

#include "debugflag.h"

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

/**
 * This function handles a create2-Response.
 * It must change the dataLen entry in the stat.
 **/
int handleCreateResponse(struct iarchive *ia, struct oarchive *oa, int32_t errorcode) {
	struct CreateResponse resp;
	deserialize_CreateResponse(ia, "reply", &resp);
	if (errorcode == 0) {
		decrypt_path(&(resp.path));
	}
	serialize_CreateResponse(oa, "reply", &resp);
	if (errorcode == 0) {
		deallocate_CreateResponse(&resp);
	}
	return 1;
}

char handleCreate2Response(struct iarchive *ia, struct oarchive *oa, int32_t errorcode) {
	struct Create2Response c2Rsp;
	deserialize_Create2Response(ia, "reply", &c2Rsp);
	if (errorcode == 0) {
		decrypt_metadata(&(c2Rsp.stat));
	}
	serialize_Create2Response(oa, "reply", &c2Rsp);
	deallocate_Create2Response(&c2Rsp);
	return 1;
}

/**
 * This function handles an exists-Response.
 * It must change the dataLen entry in the stat.
 **/
void handleExistsResponse(struct iarchive *ia, struct oarchive *oa, int32_t errorcode) {
	if (errorcode == 0) {
		struct ExistsResponse eRsp;
		deserialize_ExistsResponse(ia, "reply", &eRsp);
		//Modify eRsp.stat;
		decrypt_metadata(&(eRsp.stat));
		serialize_ExistsResponse(oa, "reply", &eRsp);
		deallocate_ExistsResponse(&eRsp);
	}
}

/**
 * This function handles a getData-Response.
 * It must decrypt the payload/data.
 * It must change the dataLen entry in the stat.
 **/
void handleGetDataResponse(struct iarchive *ia, struct oarchive *oa, int32_t errorcode, char * pathHash) {
	if (errorcode == 0) {
		struct GetDataResponse gDrsp;
		deserialize_GetDataResponse(ia, "reply", &gDrsp);
		//Decrypt gDrsp.data;
		decrypt_payload(&(gDrsp.data.buff), &(gDrsp.data.len), pathHash);
		decrypt_metadata(&(gDrsp.stat));
		serialize_GetDataResponse(oa, "reply", &gDrsp);
		deallocate_GetDataResponse(&gDrsp);
	}

}

/**
 * This function handles a setData-Response.
 * It must change the dataLen entry in the stat.
 **/
void handleSetDataResponse(struct iarchive *ia, struct oarchive *oa, int32_t errorcode) {
	if (errorcode == 0) {
		struct SetDataResponse sDrsp;
		deserialize_SetDataResponse(ia, "reply", &sDrsp);
		//Modify sDrsp.stat;
		decrypt_metadata(&(sDrsp.stat));
		serialize_SetDataResponse(oa, "reply", &sDrsp);
		deallocate_SetDataResponse(&sDrsp);
	}
}

/**
 * This function handles a getACL-Response.
 * It does not have to decrypt the ACL vector.
 * It must change the dataLen entry in the stat.
 **/
void handleGetACLResponse(struct iarchive *ia, struct oarchive *oa, int32_t errorcode) {

	struct GetACLResponse gArsp;
	deserialize_GetACLResponse(ia, "reply", &gArsp);
	//Modify gArsp.stat;
	if (errorcode == 0) {
		decrypt_metadata(&(gArsp.stat));
	}
	serialize_GetACLResponse(oa, "reply", &gArsp);
	deallocate_GetACLResponse(&gArsp);

}

/**
 * This function handles a setACL-Response.
 * It must change the dataLen entry in the stat.
 **/
void handleSetACLResponse(struct iarchive *ia, struct oarchive *oa, int32_t errorcode) {

	struct SetACLResponse sArsp;
	deserialize_SetACLResponse(ia, "reply", &sArsp);
	//Decrypt sArsp.stat;
	if (errorcode == 0) {
		decrypt_metadata(&(sArsp.stat));
	}
	serialize_SetACLResponse(oa, "reply", &sArsp);
	deallocate_SetACLResponse(&sArsp);

}

static void decrypt_children_data(struct GetChildrenResponse* resp) {
	int i;
	for (i = 0; i < resp->children.count; i++) {
		if (resp->children.data[i] == 0) {
//			printf("children.data[i] == 0.\n");
			continue;
		}
		if (!strcmp(resp->children.data[i], "zookeeper")) {
//			printf("skipping %s.\n", resp->children.data[i]);
			continue;
		}
//		printf("decrypt: %s.\n", resp->children.data[i]);
		size_t len = strlen(resp->children.data[i]);
//		printf("  len: %d.\n", (int)len);
		char* decrypted = decrypt_chunk(resp->children.data[i], &len);
//		printf("decrypted: %s.\n", decrypted);
#ifdef MMGT
		printf("%s:%s:%d: free(%p).\n", __FILE__, __FUNCTION__, __LINE__, resp->children.data[i]);
#endif
		free(resp->children.data[i]);
		resp->children.data[i] = decrypted;
	}
}

/**
 * This function handles a getChildren-Response.
 * It must iterate over all children and decrypt them.
 * It must change the dataLen entry in the stat.
 **/
void handleGetChildren2Response(struct iarchive *ia, struct oarchive *oa, int32_t errorcode) {

	struct GetChildren2Response resp;
	deserialize_GetChildren2Response(ia, "reply", &resp);
	//Modify resp.stat
	if (errorcode == 0) {
		decrypt_metadata(&(resp.stat));
		decrypt_children_data((struct GetChildrenResponse*) &resp);
	}

	serialize_GetChildren2Response(oa, "reply", &resp);
	deallocate_GetChildren2Response(&resp);

}

void handleGetChildrenResponse(struct iarchive *ia, struct oarchive *oa, int32_t errorcode) {
	struct GetChildrenResponse resp;

	deserialize_GetChildrenResponse(ia, "reply", &resp);
	if (errorcode == 0) {
		decrypt_children_data(&resp);
	}
	serialize_GetChildrenResponse(oa, "reply", &resp);
	deallocate_GetChildrenResponse(&resp);
}

void handleMultiResponse(struct iarchive *ia, struct oarchive *oa, char * pathHash);
/**
 * This function chooses a function,
 * which handles the operation given by the type.
 **/

int handleResponseType(enum OpCode type, struct iarchive * ia, struct oarchive *oa, int32_t errorcode, char * pathHash) {
#ifdef RESPONSES
	printf("### Response: %s (%d), error: %d.\n", getStringForEnum(type), (int) type, errorcode);
#endif

#if defined(DEMO)
	printf("%sProcessing %s response...%s\n", KGRN, getStringForEnum(type), KNRM);
#endif

	switch (type) {
	// payload encryption (and path):
	case create:
		handleCreateResponse(ia, oa, errorcode);
		break;
	case create2: // includes stat
		handleCreate2Response(ia, oa, errorcode);
		break;
	case exists: //Stat only
		handleExistsResponse(ia, oa, errorcode);
		break;
	case getData:
		handleGetDataResponse(ia, oa, errorcode, pathHash);
		break;
	case setData: //Stat only
		handleSetDataResponse(ia, oa, errorcode);
		break;
	case getACL:
		handleGetACLResponse(ia, oa, errorcode);
		break;
	case setACL: //Stat only
		handleSetACLResponse(ia, oa, errorcode);
		break;
	case multi:
		handleMultiResponse(ia, oa, pathHash);
		break;
		// path encryption only:
	case getChildren:
		handleGetChildrenResponse(ia, oa, errorcode);
		break;
	case getChildren2: // includes stat
		handleGetChildren2Response(ia, oa, errorcode);
		break;
		// nothing to do:
	case remv:
	case synch:
	case notification:
	case ping:
	case checkWatches:
	case check: //No response?
	case reconfig:
	case removeWatches:
	case createContainer:
	case deleteContainer:
	case auth:
	case setWatches:
	case sasl:
	case createSession:
	case closeSession:
	case error:
		return 0;
	}
	return 1;

}

/**
 * This function handles a multi-Response.
 * It invokes a handleType for every request in the multi-Request.
 **/
void handleMultiResponse(struct iarchive *ia, struct oarchive *oa, char * pathHash) {

	struct MultiHeader mh;
	struct ErrorResponse err;
	deserialize_MultiHeader(ia, "multiheader", &mh);
	while (!mh.done) {
		serialize_MultiHeader(oa, "multiheader", &mh);
#ifdef DEBUG
		printf("Type: %d\n Error: %d \n", mh.type, mh.err);
#endif
		if (mh.type != error) {
			handleResponseType(mh.type, ia, oa, mh.err, pathHash);
		} else {
			deserialize_ErrorResponse(ia, "err", &err);
			serialize_ErrorResponse(oa, "err", &err);
		}
		deserialize_MultiHeader(ia, "multiheader", &mh);
	}
	serialize_MultiHeader(oa, "multiheader", &mh);

}

/**
 * This function parse the responses from the zk-server.
 * It gets the type/opCde(e.g create or delete) from a queue with the sequence number as a key.
 * If changes to the input archive pointed to by ia were made, 
 * they are stored in the output archive pointed to by oa.
 * 1 is returned.
 * Returns 2 if, the response should go back to zookeeper(e.g create -> multi)
 * Otherwise no changes were made 
 * */
int handle_response(package_t * p_package, list_t * p_list) {

	int package_changed = 0;
	struct ReplyHeader responseHdr;
	char * pathHash;

	//Archives (from the ZK-C-API) for
	struct iarchive *ia = create_buffer_iarchive(p_package->buffer, p_package->size);
	struct oarchive *oa = create_buffer_oarchive();

	deserialize_ReplyHeader(ia, "hdr", &responseHdr);

	if (responseHdr.err != 0) {
		if (responseHdr.err == -110) {
			printf("Error code %d in response header (110=NOEEXISTS)!\n", responseHdr.err);
		} else if(responseHdr.err == -101) {
			printf("Error code %d in response header (101=NONODE)!\n", responseHdr.err);
		} else {
			printf("Error code %d in response header!\n", responseHdr.err);
		}
	}

	// retrieve hash(plainpath) from list
	pathHash = (char*)malloc(HASHLEN);
	int type = removeEnd(p_list, responseHdr.xid, pathHash);

	serialize_ReplyHeader(oa, "hdr", &responseHdr);

	package_changed = handleResponseType(type, ia, oa, responseHdr.err, pathHash);

	if (package_changed) {
		char * tmp_oa = get_buffer(oa);
		p_package->size = get_buffer_len(oa);
		memcpy(p_package->buffer, tmp_oa, p_package->size);
	}

	close_buffer_oarchive(&oa, 1);
	close_buffer_iarchive(&ia);

	free(pathHash);

	return package_changed;

}
