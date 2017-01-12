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
package org.apache.zookeeper.server;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Arrays;

/**
 * This class is the JNI bridge to for the enclave.
 * The name ZPP origins from ZooKeeper Privacy Proxy (an internal working title for this project)
 */

public class Zpp {
	private static final Logger LOG = LoggerFactory.getLogger(Zpp.class);

	static {
		System.loadLibrary("zppjni");
	}

	private static int zpps = 0;
	private long enclaveid;

	native long initEnclave();

	native byte[] requestIntoZpp(byte[] array, long enclaveid);

	native byte[] responseIntoZpp(byte[] array, long enclaveid);

	public Zpp() {
		LOG.debug("Initializing Enclave...");
		enclaveid = initEnclave();
		LOG.debug("Enclave ID: " + enclaveid);
	}

	public long getEnclaveID() {
		return enclaveid;
	}

	public byte[] handleRequest(byte[] array) {
		LOG.debug("Request before JNI call (" + array.length + ")\n" + DatatypeConverter.printHexBinary(array));
		byte[] array_zppjni = requestIntoZpp(array, enclaveid);
		LOG.debug("Request after JNI call (" + array_zppjni.length + ")\n" + DatatypeConverter.printHexBinary(array_zppjni));
		return array_zppjni;
	}

	public byte[] handleResponse(byte[] array) {
		LOG.debug("Response before JNI call (" + array.length + ")\n" + DatatypeConverter.printHexBinary(array));
		byte[] array_zppjni = responseIntoZpp(array, enclaveid);
		LOG.debug("Response after JNI call (" + array_zppjni.length + ")\n" + DatatypeConverter.printHexBinary(array_zppjni));
		return array_zppjni;
	}

}
