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

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.DownstreamMessageEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.handler.codec.frame.FrameDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;

import javax.xml.bind.DatatypeConverter;

/**
 * This handler is added to the processing chain, similar to the SSL Handler.
 * It intercepts requests and response and forwards them via the ZPP class 
 * to the enclave, where the cryptography part is done.
 */
public class ZppHandler extends FrameDecoder implements ChannelDownstreamHandler {

	private static final Logger LOG = LoggerFactory.getLogger(ZppHandler.class);

	public ZppHandler() {
	}

	@Override
	public void handleDownstream(ChannelHandlerContext context, ChannelEvent event) throws Exception {
		// message from zookeeper to client

		if (!(event instanceof MessageEvent)) {
			context.sendDownstream(event);
			return;
		}

		MessageEvent e = (MessageEvent) event;
		if (!(e.getMessage() instanceof ChannelBuffer)) {
			context.sendDownstream(event);
			return;
		}

		// Otherwise, all messages are encrypted.
		ChannelBuffer buffer = (ChannelBuffer) e.getMessage();
		if (buffer.readableBytes() < 4) {
			return;
		}
		buffer.markReaderIndex();

		int length = buffer.readInt();

		if (buffer.readableBytes() < length) {
			buffer.resetReaderIndex();
			return;
		}

		// copy complete message (without length) to array
		byte[] array = buffer.copy(buffer.readerIndex(), length).toByteBuffer().array();
		buffer.skipBytes(length);
		byte[] array_encrypted = null;
		LOG.debug("Got response, forwarding to ZPP, len=" + length +".");
		Zpp zpp = (Zpp) context.getAttachment();
		if (zpp != null) {
			array_encrypted = zpp.handleResponse(array);
		} else {
			LOG.debug("ZPP is null");
		}
		LOG.debug("ZPP processed response.");

		ChannelBuffer frame = ChannelBuffers.buffer(array_encrypted.length + 4);
		frame.writeInt(array_encrypted.length);
		frame.writeBytes(array_encrypted);

		event = new DownstreamMessageEvent(e.getChannel(), e.getFuture(), frame, e.getChannel().getRemoteAddress());

		context.sendDownstream(event);

	}

	@Override
	protected Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
		// messages from client to zookeeper
		if (buffer.readableBytes() < 4) {
			return null;
		}
		buffer.markReaderIndex();
		
		int length = buffer.readInt();

		if (buffer.readableBytes() < length) {
			buffer.resetReaderIndex();
			return null;
		}
		byte[] array;
		try {
			 array= buffer.copy(buffer.readerIndex(), length).toByteBuffer().array();
		} catch(Exception e) {
			LOG.error("length: " + length + " " + ", buffer.readerIndex():" + buffer.readerIndex() + ", " + e.getMessage());
			if(length < 0 || length > 1024) length = 32;
			LOG.error(buffer.toString(buffer.readerIndex(), length, Charset.defaultCharset()));
			throw e;
		}
		buffer.skipBytes(length);

		byte[] array_decrypted = null;
		Zpp zpp = (Zpp) ctx.getAttachment();
		if (zpp != null) {
			LOG.debug("Got request, forwarding to ZPP.");    
			array_decrypted = zpp.handleRequest(array);
			LOG.debug("Decrypted Request: " + DatatypeConverter.printHexBinary(array_decrypted));
			LOG.debug("ZPP processed request.");    
		} else {
			LOG.debug("ZPP null");
		}

		ChannelBuffer frame = ChannelBuffers.buffer(array_decrypted.length + 4);
		frame.writeInt(array_decrypted.length);
		frame.writeBytes(array_decrypted);

		return frame;
	}

	@Override
	public void channelConnected(ChannelHandlerContext ctx, ChannelStateEvent e) {
		LOG.debug("New connection.");
		ctx.setAttachment(new Zpp());
		ctx.sendUpstream(e);
	}

}
