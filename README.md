# SecureKeeper
Secure ZooKeeper using Intel SGX

This README assumes, that the symbolic link 'zookeeper' directs 
to 'zookeeper-3.5.1-alpha'.
Everything from now on is done within the 'zookeeper' directory.

BUILD
-------------
Invoke 'ant' in the zookeeper directory.

SERVER
-------------
Create a 'zoo.cfg' file inside 'conf/' (e.g. by copying 'zoo.cfg.sample').  
Note: For a single node ZooKeeper instance, remove the last line of the file.

Now the server can be started by calling './start-foreground.sh none|ssl|sgx'.  
Note: To use a replicated ZooKeeper cluster, change the IP-addresses 
in the 'conf/zoo.cfg.dynamic.100000000.sample' file.  
Furthermore, add '/FULL/PATH/TO/zookeeper/conf/dynamicConfigFile=conf/zoo.cfg.dynamic.100000000' 
at the end of your 'zoo.cfg' file.

To delete all ZooKeeper application data remove the directory given in the 'cfg' file (e.g. '/tmp/zookeeper').

CLIENT
-------------
Execute 'bin/zkCli.sh none|ssl|sgx -server SERVER_IP'.

Note: *ssl* and *sgx* work only if the corresponding option is chosen on the server side.


Examples
-------------
First, setup the config file.
Afterwards, invoke './start-foreground.sh sgx' on the server and './bin/zkCli.sh sgx -server SERVER_IP' on the client side.
An interactive shell should be available after hitting the return key.  

**Creating Nodes**  
The command 'ls /' should list all existing nodes.
Only 'zookeeper' exists after a fresh start.
Create a node by using 'create /nodeA payloadA',
and more by using 'create /nodeB' and 'create -s /nodeC payloadC'.  
You can check the existing nodes by using 'ls /'.
This should result in '[nodeA, nodeB, nodeC0000000002, zookeeper]'.  
Note: The sequence number, appended to nodeC depends on the number of already created nodes.  
To verify this, you can 'create /nodeD' and 'delete /nodeD'.  
After having issued 'create -s /nodeE',
'ls /' will give you '[nodeA, nodeB, nodeC0000000002, nodeE0000000004, zookeeper]'.  

**Creating Children**  
Until now, there are none of the created nodes have child nodes.  
Thus invoke 'create /nodeA/childA' and 'create /nodeA/childB'.
To see the children call 'ls /nodeA'.

**Getting and setting payload**  
Check the payload of *nodeA* by invoking 'get /nodeA'.
This should return 'payloadA'.
Change it to *payloadAv2* by using 'set /nodeA payloadAv2'.
Another 'get/ nodeA' will show you, that the payload was changed.
This can be done with any node.
Getting the payload of *nodeB* will give you an empty string.

**Without SGX**  
Kill the client and server using 'CTRL + C' and restart them by invoking:  
'./start-foreground.sh ssl' and './bin/zkCli.sh ssl -server SERVER_IP'.  
Don't remove the data directory on the server.  
Call 'ls /' and you can see, the encrypted node names.
Invoking *get* on the nodes will return an encrypted payload.

Additional Java Files and Changes
-------------
To implement SecureKeeper, a few Java files had to be changed and created.  
These are listed below:  
**Additional Java Files**  
In 'src/java/main/org/apache/zookeeper/':  
'server/SeqEnclave.java'  
'server/ZppHandler.java'  
'server/Zpp.java'  
'ZKClientCryptoHandler.java'  
**Changes to existing Java Files**   
In 'src/java/main/org/apache/zookeeper/':  
'server/NettyServerCnxnFactory.java'  
'server/PrepRequestProcessor.java'  
'ClientCnxnSocketNetty.java'
