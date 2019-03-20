from unittest import TestCase


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
