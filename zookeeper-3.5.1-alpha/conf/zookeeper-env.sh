#!/usr/bin/env bash

export SERVER_JVMFLAGS="
-Dzookeeper.serverCnxnFactory=org.apache.zookeeper.server.NettyServerCnxnFactory
-Dzookeeper.ssl.keyStore.location=$PWD/testKeyStore.jks 
-Dzookeeper.ssl.keyStore.password=testpass 
-Dzookeeper.ssl.trustStore.location=$PWD/testTrustStore.jks 
-Dzookeeper.ssl.trustStore.password=testpass" 

export CLIENT_JVMFLAGS_SSL="
-Dzookeeper.clientCnxnSocket=org.apache.zookeeper.ClientCnxnSocketNetty
-Dzookeeper.client.secure=true 
-Dzookeeper.ssl.keyStore.location=$PWD/testKeyStore.jks 
-Dzookeeper.ssl.keyStore.password=testpass 
-Dzookeeper.ssl.trustStore.location=$PWD/testTrustStore.jks 
-Dzookeeper.ssl.trustStore.password=testpass
-Dzpp=false"


export CLIENT_JVMFLAGS_SGX="
-Dzookeeper.clientCnxnSocket=org.apache.zookeeper.ClientCnxnSocketNetty
-Dzookeeper.client.secure=true 
-Dzookeeper.ssl.keyStore.location=$PWD/testKeyStore.jks 
-Dzookeeper.ssl.keyStore.password=testpass 
-Dzookeeper.ssl.trustStore.location=$PWD/testTrustStore.jks 
-Dzookeeper.ssl.trustStore.password=testpass
-Dzpp=true"

export CLIENT_JVMFLAGS_NONE="
-Dzookeeper.clientCnxnSocket=org.apache.zookeeper.ClientCnxnSocketNetty
-Dzookeeper.client.secure=false
-Dzpp=false"

export ZOO_LOG4J_PROP='DEBUG,TRACEFILE' 
