import unittest
import demo_server
from unittest.mock import Mock, patch

from time import sleep
import paramiko


class UnitTestServer(unittest.TestCase):
    def setUp(self):
        self.server = demo_server.Server()

    def test_check_auth_password_success(self):
        result = self.server.check_auth_password("admin", "admin")
        self.assertEqual(result, paramiko.AUTH_SUCCESSFUL)

    def test_check_auth_password_empty(self):
        result = self.server.check_auth_password("admin", "")
        self.assertEqual(result, paramiko.AUTH_SUCCESSFUL)       

    def test_check_auth_key_failure(self):
        key = paramiko.RSAKey.generate(1024)
        result = self.server.check_auth_publickey("user", key)
        self.assertEqual(result, paramiko.AUTH_FAILED)

    def test_check_channel_request_session(self):
        result = self.server.check_channel_request("session", 1)
        self.assertEqual(result, paramiko.OPEN_SUCCEEDED)

    def test_check_channel_request_invalid(self):
        result = self.server.check_channel_request("direct-tcpip", 1)
        self.assertEqual(result, paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)


if __name__ == '__main__':
    unittest.main()
