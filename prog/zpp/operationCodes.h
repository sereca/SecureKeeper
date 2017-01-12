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
#ifndef _OPERATION_CODES_H_
#define _OPERATION_CODES_H_

/**
 * This file is adapted from "org.java.apache.zookeeper.Zoodefs.java"
 * It represents the operations codes / types used for communication 
 * in the protocol of zookeeper.
 **/
enum OpCode {
	notification = 0,
	create = 1,
	remv = 2,
	exists = 3,
	getData = 4,
	setData = 5,
	getACL = 6,
	setACL = 7,
	getChildren = 8,
	synch = 9,
	ping = 11,
	getChildren2 = 12,
	check = 13,
	multi = 14,
	create2 = 15,
	reconfig = 16,
	checkWatches = 17,
	removeWatches = 18,
	createContainer = 19,
	deleteContainer = 20,
	auth = 100,
	setWatches = 101,
	sasl = 102,
	createSession = -10,
	closeSession = -11,
	error = -1
};

/**
 * This function returns a string for a given opCode
 * Only for debugging purposes
 * */
static inline const char *getStringForEnum(enum OpCode opCode) {

	static const char *firstOpCodes[] = { "notification", "create", "delete",
			"exists", "getData", "setData", "getACL", "setACL", "getChildren",
			"sync" };

	static const char *secondOpCodes[] = { "ping", "getChildren2", "check",
			"multi", "create2", "reconfig", "removeWatches" };

	static const char *thirdOpCodes[] = { "auth", "setWatches", "sasl" };

	if (opCode == -1) {
		return "error";
	} else if (opCode == -10) {
		return "createSession";
	} else if (opCode == -11) {
		return "closeSession";
	}

	if (opCode >= 0 && opCode < 10) {
		return firstOpCodes[opCode];
	} else if (opCode > 10 && opCode < 100) {
		return secondOpCodes[opCode - 11];
	} else if (opCode >= 100 && opCode <= 102) {
		return thirdOpCodes[opCode - 100];
	}

	return "Unknown";

}
#endif
