# Conductor

Conductor is an easy to use utility to generate self-signed Certificate Authority chains.
Initially Conductor was written as a testing tool to easily generate certificates for testing
TLS applications written in C, and for fun!

## How to

    conductor gen server server.domain.tld -i 192.168.1.1 -d service.domain.tld

In a empty directory this will generate you a Certificate Authority Cert/Key,
an Intermediate Certificate Authority Cert/Key, and a server x.509 cert/key and fullchain.

Next generate a user cert.

    conductor gen user dan

It's that easy!

## Installing

Conductor has a few prerequisites; make, flex, and bison. After those are install all you need to run is:

    make

And you'll be able to run conductor right from the repo. Otherwise you can run:

    sudo make install

And by default this will install to /usr/local/bin, of course this is configurable with PREFIX and DESTDIR.
