# edutls
implementation of rfc8446 TLS 1.3 in pure python (educational purpose)

# design

  as is mainly for education of TLS 1.3 standard published in 2018, it uses almost all of the concepts 

and key words for naming.

  it implements the protocol process as state machine noted in rfc8446 Appendix A.1(client side).no server side support yet.

files layout:

```
edutls/
	|
	|
	alert.py  		--alert message serialize/deserialize
	extension.py	--extensions used in handshake message serialize/deserialize
	handshake.py	--handshake message serialize/deserialize
	record.py		--record protocol. all messages should be encoded in it to transmit
	keys.py			--key derivation implementations
	types.py		--fundamental objects for serialization/deserialization
	tls13.py		--tls1.3 protocol process implemeted as state machine
tests.py	--a simple test for tls1.3 client
```

## client state machine

![client-state-machine](doc/client-state-machine.png)

# test server

[tls13-spec test server](https://github.com/tlswg/tls13-spec/wiki/Implementations)