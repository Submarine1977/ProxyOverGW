#!/bin/sh

nohup ../build/bin/ProxyC/proxyc 127.0.0.1 8080 127.0.0.1 8888 &
nohup ../build/bin/ProxyF/proxyf 8888 &
