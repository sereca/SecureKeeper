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

/**
 * This class is the JNI bridge to for the sequential enclave.
 */

public class SeqEnclave {
	private static final Logger LOG = LoggerFactory.getLogger(Zpp.class);

	static {
		System.loadLibrary("seqencljni");
	}

	private int enclaveid;

	native int initEnclave();

	public native byte[] getSequentialPath(byte[] array, int length);

	private static SeqEnclave instance = null;

	private SeqEnclave() {
		LOG.debug("SeqEnclave constructor.");
		enclaveid = initEnclave();
		if(enclaveid > 0)
			LOG.info("=== Created sequential enclave with ID: " + enclaveid);
		else
			LOG.error("=== Error creating sequential enclave. ret=" + enclaveid + "!");
	}

	public static synchronized SeqEnclave getInstance() {
		if (instance == null) {
			instance = new SeqEnclave();
		}
		return instance;
	}

	public byte[] getSequentialPath2(byte[] array, int length)
	{
		LOG.debug("PathBytes right before JNI call: " + DatatypeConverter.printHexBinary(array) + ", length: " + length);
		return getSequentialPath(array, length);
	}
}
