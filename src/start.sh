#!/bin/sh

nohup ../build/bin/ProxyC/proxyc 192.168.154.128 8080 127.0.0.1 8888 &
nohup ../build/bin/ProxyF/proxyf 8888 &
