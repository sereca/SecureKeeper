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
enum ZOO_ERRORS {
	ZOK = 0, /*!< Everything is OK */

	/** System and server-side errors.
	 * This is never thrown by the server, it shouldn't be used other than
	 * to indicate a range. Specifically error codes greater than this
	 * value, but lesser than {@link #ZAPIERROR}, are system errors. */
	ZSYSTEMERROR = -1,
	ZRUNTIMEINCONSISTENCY = -2, /*!< A runtime inconsistency was found */
	ZDATAINCONSISTENCY = -3, /*!< A data inconsistency was found */
	ZCONNECTIONLOSS = -4, /*!< Connection to the server has been lost */
	ZMARSHALLINGERROR = -5, /*!< Error while marshalling or unmarshalling data */
	ZUNIMPLEMENTED = -6, /*!< Operation is unimplemented */
	ZOPERATIONTIMEOUT = -7, /*!< Operation timeout */
	ZBADARGUMENTS = -8, /*!< Invalid arguments */
	ZINVALIDSTATE = -9, /*!< Invliad zhandle state */

	/** API errors.
	 * This is never thrown by the server, it shouldn't be used other than
	 * to indicate a range. Specifically error codes greater than this
	 * value are API errors (while values less than this indicate a 
	 * {@link #ZSYSTEMERROR}).
	 */
	ZAPIERROR = -100,
	ZNONODE = -101, /*!< Node does not exist */
	ZNOAUTH = -102, /*!< Not authenticated */
	ZBADVERSION = -103, /*!< Version conflict */
	ZNOCHILDRENFOREPHEMERALS = -108, /*!< Ephemeral nodes may not have children */
	ZNODEEXISTS = -110, /*!< The node already exists */
	ZNOTEMPTY = -111, /*!< The node has children */
	ZSESSIONEXPIRED = -112, /*!< The session has been expired by the server */
	ZINVALIDCALLBACK = -113, /*!< Invalid callback specified */
	ZINVALIDACL = -114, /*!< Invalid ACL specified */
	ZAUTHFAILED = -115, /*!< Client authentication failed */
	ZCLOSING = -116, /*!< ZooKeeper is closing */
	ZNOTHING = -117, /*!< (not error) no server responses to process */
	ZSESSIONMOVED = -118 /*!<session moved to another server, so operation is ignored */
};
