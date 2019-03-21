from unittest import TestCase

from edutls.extension import NamedGroup


class KeyExchangeTest(TestCase):
    def test_dh(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import dh
        for i in range(2):
            parameters: dh.DHParameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            parameter_numbers: dh.DHParameterNumbers = parameters.parameter_numbers()
            private_key: dh.DHPrivateKey = parameters.generate_private_key()
            peer_parameters: dh.DHParameters = private_key.parameters()
            peer_parameter_numbers: dh.DHParameterNumbers = peer_parameters.parameter_numbers()
            print(parameter_numbers.p, parameter_numbers.g, peer_parameter_numbers.p, peer_parameter_numbers.g)

    def test_shared_key(self):
        from edutls.extension import KeyExchange
        for group in NamedGroup:
            k1 = KeyExchange(group)
            k1_pub = k1.pack()
            print(len(k1_pub))
            k2 = KeyExchange(group)
            k2_pub = k2.pack()
            shared1 = k1.exchange(k2_pub)
            shared2 = k2.exchange(k1_pub)
            assert shared1 == shared2
            print(f"{group.name} k1_pub len:{len(k1_pub)} k2_pub len:{len(k2_pub)} shared key len:{len(shared1)}")


class TLSClientTest(TestCase):
    def test_client(self):
        import asyncio
        import time
        from edutls.tls13 import TLSClientMachine
        host, port = ("tls13.pinterjann.is", 443)
        http_req = b'GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: tls13-tester\r\nAccept: */*\r\n\r\n' % host.encode()
        tls_client = TLSClientMachine()
        tls_client.write_application_data_async(http_req)
        asyncio.run(tls_client.connect(host, port))
        tls_client.write_application_data_async(http_req)
        tls_client.reset()
        asyncio.run(tls_client.connect(host, port))
        time.sleep(1200)
