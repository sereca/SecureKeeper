#!/bin/bash
echo "mode $1"
bin/zkServer.sh start-foreground conf/zoo.cfg $1
