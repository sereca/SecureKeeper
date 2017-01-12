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
 * These functions deal with the bytes coming from the connected client.
 * They always deserialize, encode and serialize the data.
 **/

#include <unistd.h> //basename
#include <stdlib.h>
#include <string.h>

#include "requestHandler.h"
#include "crypto.h"
#include "operationCodes.h"
#include "zookeeper.jute.h"
#include "list.h"
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
 * Predefining for use in handleMulti
 **/
int handleRequestType(enum OpCode type, struct iarchive *ia, struct oarchive *oa, struct GetDataRequest *gdr);

/**
 * This function handles a create-Request.
 * It must encrypt the path name.
 * But first it must try to encode the payload(data),
 * but only if it does not contain quota information.
 * It must not encode the flags for ephemeral or sequential.
 * It must not encode the vector for the access control list.
 **/
void handleCreateRequest(struct iarchive *ia, struct oarchive *oa) {

	int i, aclCount;
	struct CreateRequest cReq;
	deserialize_CreateRequest(ia, "req", &cReq);

	encrypt_payload(&(cReq.data.buff), &(cReq.data.len), cReq.path);
	encrypt_path(&(cReq.path));

//	aclCount = cReq.acl.count;
//	for(i=0; i<aclCount; i++) {
//		printf("ACL(%d): %p\n", i, cReq.acl.data[i]);
//	}
	serialize_CreateRequest(oa, "req", &cReq);
	deallocate_CreateRequest(&cReq);
}

/**
 * This function handles a create2-Request, which is equal to the 
 * create-Request.
 **/
void handleCreate2Request(struct iarchive *ia, struct oarchive *oa) {
	handleCreateRequest(ia, oa);
}

/**
 * This function handles a setData-Request.
 * It must encrypt the path name.
 * But first it must try to encode the payload(data),
 * but only if it does not contain quota information.
 * It must not encode the version number.
 **/
void handleSetDataRequest(struct iarchive *ia, struct oarchive *oa) {

	struct SetDataRequest sDreq;
	deserialize_SetDataRequest(ia, "req", &sDreq);

	encrypt_payload(&(sDreq.data.buff), &(sDreq.data.len), sDreq.path);
	encrypt_path(&(sDreq.path));

	serialize_SetDataRequest(oa, "req", &sDreq);
	deallocate_SetDataRequest(&sDreq);

}

/**
 * This function handles a multi-Request.
 * It invokes a handleType for every request in the multi-Request.
 **/
void handleMultiRequest(struct iarchive *ia, struct oarchive *oa, struct GetDataRequest* gdr) {

	struct MultiHeader mh;
	deserialize_MultiHeader(ia, "multiheader", &mh);

	while (!mh.done) {
		serialize_MultiHeader(oa, "multiheader", &mh);

		handleRequestType(mh.type, ia, oa, gdr);

		deserialize_MultiHeader(ia, "multiheader", &mh);
	}

}

void handleGetDataRequest(struct iarchive *ia, struct oarchive *oa, struct GetDataRequest* gdr)
{
	// special: in this case deserialization done earlier
	//   in handle_request(), can not be done again here
	encrypt_path(&(gdr->path));
	serialize_GetDataRequest(oa, "req", gdr);
}
void handleGetChildrenRequest(struct iarchive *ia, struct oarchive *oa)
{
	struct GetChildrenRequest req;
	deserialize_GetChildrenRequest(ia, "req", &req);
	encrypt_path(&(req.path));
	serialize_GetChildrenRequest(oa, "req", &req);
	deallocate_GetChildrenRequest(&req);
}
void handleGetChildren2Request(struct iarchive *ia, struct oarchive *oa)
{
	handleGetChildrenRequest(ia, oa);
}
void handleDeleteRequest(struct iarchive *ia, struct oarchive *oa)
{
	struct DeleteRequest gDreq;
	deserialize_DeleteRequest(ia, "req", &gDreq);

	encrypt_path(&(gDreq.path));

	serialize_DeleteRequest(oa, "req", &gDreq);
	deallocate_DeleteRequest(&gDreq);
}
void handleExistsRequest(struct iarchive *ia, struct oarchive *oa)
{
	struct ExistsRequest gDreq;
	deserialize_ExistsRequest(ia, "req", &gDreq);

	encrypt_path(&(gDreq.path));

	serialize_ExistsRequest(oa, "req", &gDreq);
	deallocate_ExistsRequest(&gDreq);
}
void handleGetAclRequest(struct iarchive *ia, struct oarchive *oa)
{
	 struct GetACLRequest gDreq;
	 deserialize_GetACLRequest(ia, "req", &gDreq);

	 encrypt_path(&(gDreq.path));

	 serialize_GetACLRequest(oa, "req", &gDreq);
	 deallocate_GetACLRequest(&gDreq);
}
void handleSetAclRequest(struct iarchive *ia, struct oarchive *oa)
{
	 struct SetACLRequest gDreq;
	 deserialize_SetACLRequest(ia, "req", &gDreq);

	 encrypt_path(&(gDreq.path));

	 serialize_SetACLRequest(oa, "req", &gDreq);
	 deallocate_SetACLRequest(&gDreq);
}

/**
 * This function chooses a function, 
 * which handles the operation given by the type.
 * Returns 0 if nothing has been changed, 1 otherwise.
 **/
int handleRequestType(enum OpCode type, struct iarchive * ia, struct oarchive *oa, struct GetDataRequest* gdr) {
#ifdef REQUESTS
	printf("### Request: %s (%d).\n", getStringForEnum(type), (int)type);
#endif

#if defined(DEMO)
	printf("%sProcessing %s request...%s\n", KGRN, getStringForEnum(type), KNRM);
#endif

	switch (type) {
	// payload encryption (and path):
	case create:
		handleCreateRequest(ia, oa);
		break;
	case create2: // includes stat
		handleCreate2Request(ia, oa);
		break;
	case setData:
		handleSetDataRequest(ia, oa);
		break;
	// path encryption only:
	case getData:
		handleGetDataRequest(ia, oa, gdr);
		break;
	case getChildren:
		handleGetChildrenRequest(ia, oa);
		break;
	case getChildren2: // includes stat
		handleGetChildren2Request(ia, oa);
		break;
	case remv:
		handleDeleteRequest(ia, oa);
		break;
	case exists:
		handleExistsRequest(ia, oa);
		break;
	// nothing to do:
	case getACL:
		 handleGetAclRequest(ia, oa);
		 break;
	case setACL:
		 handleSetAclRequest(ia, oa);
		 break;
	case synch:
	case multi:
		//TODO: path encryption here?
	case setWatches:
	case removeWatches:
	case createContainer:
	case deleteContainer:
	case check:
	case checkWatches:
	case auth:
	case sasl:
	case createSession:
		//Connect request, nothing to encode
	case closeSession:
	case notification:
	case ping:
		//Handled in the functions which is calling handleRequest;
	case reconfig:
		//Nothing to encode
	case error:
		return 0;
	default:
		printf("Warning: %s -> switch-case=default, type=%d.\n", __FUNCTION__, type);
		return 0;
	}
	return 1;
}

/**
 * This function parses a request from a client.
 * It analyses the type (e.g create or delete).
 * The type is stored in a queue which the sequence nummer as a key.
 * If changes to the input archive pointed to by ia were made,
 * they are stored in the output archive pointed to by oa.
 * 1 is returned. 
 * Otherwise no changes were made and 0 is returned.
 * */
int handle_request(package_t * p_package, list_t * p_list) {

	sgx_sha256_hash_t * pathHash;
	struct RequestHeader * p_reqHdr = (struct RequestHeader *) malloc(sizeof(struct RequestHeader));
#ifdef MMGT
	printf("%s: %p = malloc(%d) -> free in response.\n", __FUNCTION__, p_reqHdr, sizeof(struct RequestHeader));
#endif
	int package_changed = 0;

	//Archives (from the ZK-C-API) for
	struct iarchive *ia = create_buffer_iarchive(p_package->buffer, p_package->size);

	struct oarchive *oa = create_buffer_oarchive();
	deserialize_RequestHeader(ia, "header", p_reqHdr);
	serialize_RequestHeader(oa, "header", p_reqHdr);

	if(p_reqHdr->type == getData) {
		struct GetDataRequest gDreq;

		// special: deserialization here, because we need the path.
		//   we need to forward the deserialized request down the
		//   call graph, because needed again later.
		deserialize_GetDataRequest(ia, "req", &gDreq);

		pathHash = (sgx_sha256_hash_t*) malloc(HASHLEN);
		// insert hash(plainpath) into list
		sgx_sha256_msg(gDreq.path, strlen(gDreq.path), pathHash);
		insertFront(p_list, p_reqHdr->xid, p_reqHdr->type, (char*)pathHash);
		free(pathHash);

		package_changed = handleRequestType(p_reqHdr->type, ia, oa, &gDreq);

		deallocate_GetDataRequest(&gDreq);
	} else {
		package_changed = handleRequestType(p_reqHdr->type, ia, oa, NULL);
		insertFront(p_list, p_reqHdr->xid, p_reqHdr->type, NULL);
	}

	if (package_changed) {
		char * tmp_oa = get_buffer(oa);
		p_package->size = get_buffer_len(oa);
		memcpy(p_package->buffer, tmp_oa, p_package->size);
	}

	free(p_reqHdr);
	close_buffer_oarchive(&oa, 1);
	close_buffer_iarchive(&ia);
	return package_changed;
}
