# proxytun

## Summary

Kinda like a socks proxy + vpn tunnel app that is multi-process & multi-threaded in c

## Setup

Needs a helper shell script to get the initial client connection state information and stdouts the destination addr:port

The vpn.txt argument on side-a has the server addr:port of side-b and the same argument is essentially ignored on side-b (set with the proxied addr:port above)

## Start

side-a: proxytun s 0.0.0.0 1337 vpn.txt key.txt

side-b: proxytun r 0.0.0.0 9050 vpn.txt key.txt

