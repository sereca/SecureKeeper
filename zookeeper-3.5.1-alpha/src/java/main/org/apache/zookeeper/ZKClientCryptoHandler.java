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
package org.apache.zookeeper;

import java.security.Key;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.DownstreamMessageEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.handler.codec.frame.FrameDecoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class intercepts the client request and server responses to apply transport encryption.
 */
public class ZKClientCryptoHandler extends FrameDecoder implements ChannelDownstreamHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ZKClientCryptoHandler.class);

    public static final boolean ACTIVE = true;

    Key key;

    byte keyBytes[] = { 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd' };
    byte aes_iv[] = { 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'd' };

    byte[] sample = new byte[256];
    byte[] encSample = new byte[256];


    public ZKClientCryptoHandler() {
        this.key = new SecretKeySpec(keyBytes, "AES");

        Arrays.fill(sample, (byte)175);
    }

    @Override
    public void handleDownstream(ChannelHandlerContext context, ChannelEvent event) throws Exception {
        // message from client to server

        if (!(event instanceof MessageEvent)) {
            context.sendDownstream(event);
            return;
        }

        MessageEvent e = (MessageEvent) event;
        if (!(e.getMessage() instanceof ChannelBuffer)) {
            context.sendDownstream(event);
            return;
        }

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
        byte[] array = buffer.copy(buffer.readerIndex(), length).toByteBuffer().array();
        buffer.skipBytes(length);


        byte[] encryptedArray = encrypt(array); 


        ChannelBuffer frame = ChannelBuffers.buffer(encryptedArray.length + 4);
        frame.writeInt(encryptedArray.length);
        frame.writeBytes(encryptedArray);
        event = new DownstreamMessageEvent(e.getChannel(), e.getFuture(), frame, e.getChannel().getRemoteAddress());

        context.sendDownstream(event);
    }

    @Override
    protected Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
        // message from server to client
        if (buffer.readableBytes() < 4) {
            return null;
        }
        buffer.markReaderIndex();

        int length = buffer.readInt();

        if (buffer.readableBytes() < length) {
            buffer.resetReaderIndex();
            return null;
        }
        byte[] array = buffer.copy(buffer.readerIndex(), length).toByteBuffer().array();
        buffer.skipBytes(length);

        byte[] decryptedArray = decrypt(array);

        ChannelBuffer frame = ChannelBuffers.buffer(decryptedArray.length + 4);
        frame.writeInt(decryptedArray.length);
        frame.writeBytes(decryptedArray);

        return frame;
    }

    private byte[] encrypt(byte[] src) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec params = new GCMParameterSpec(128, aes_iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, params);
        byte[] cipherText = cipher.doFinal(src);
        return cipherText;
    }

    private byte[] decrypt(byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        //16 Byte Tag and enc with const aes_iv
        GCMParameterSpec params = new GCMParameterSpec(128, aes_iv);
        cipher.init(Cipher.DECRYPT_MODE, key, params);
        byte[] cipherText = cipher.doFinal(message, 0, message.length);
        return cipherText;
    }
}
