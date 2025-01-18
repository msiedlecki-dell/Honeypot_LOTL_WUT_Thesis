#!/usr/bin/env python


import base64
import gc
from binascii import hexlify
import os
import socket
import sys
import threading
import traceback
import time
import random
from datetime import datetime, timedelta
from paramiko.common import (DEBUG)
import paramiko


# setup logging
paramiko.util.log_to_file("paramiko.log",level=DEBUG)

host_key = paramiko.RSAKey(filename="test_rsa.key")


class Server(paramiko.ServerInterface):

    def __init__(self):
        self.event = threading.Event()

    # No Authentication, just in case
    # def check_auth_none(self, username):
    #     if (username):
    #         return paramiko.AUTH_SUCCESSFUL
    #     return paramiko.AUTH_FAILED


    def check_channel_request(self, kind, chanid):
        print("kind: '%s', chanid:'%s'" % 
              (kind,    chanid))
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        with open("credentials.log" ,'a') as cred_file:
            cred_file.write(f"{str(datetime.now())} - {username}:{password}\n")
        print(f"Auth attempt: {password}:{username}")
        if username == "admin" and password == "admin":
            return paramiko.AUTH_SUCCESSFUL
        
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        print("Auth attempt with key: " + bytes.decode(hexlify(key.get_fingerprint())))
        print("Auth tried for username: ", username)
        with open("credentials_key.log" ,'a') as cred_file:
            cred_file.write(f"{str(datetime.now())} - {username}:{bytes.decode(hexlify(key.get_fingerprint()))}\n")
        return paramiko.AUTH_FAILED

    
    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        print("Channel: '%s'" % (channel))
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


    def check_channel_exec_request(self, channel, command):
        with open("remote_exec.log" ,'a') as log_file:
            log_file.write(f"{str(datetime.now())} - {str(channel.getpeername())} - {command.decode('utf-8')}\n")
        print("Command: '%s'" % command.decode('utf-8'))
        print("Peername: '%s'" % str(channel.getpeername()))
        self.event.set()
        return False
    
    def get_banner(self):
        banner = """
        
***********************************************
*                                             *
*         WARNING: ACCESS RESTRICTED          *
*                                             *
*   This SSH server provides access to a      *
*   administrator PowerShell station.         * 
*   Unauthorized access or misuse is strictly *
*   prohibited.                               *
*                                             *
*   All activities on this server are logged  *
*   and monitored. Any suspicious behavior    *
*   will be reported and investigated.        *
*                                             *
*   Authorized personnel only. Proceed only   *
*   if you have explicit permission to        *
*   access the system.                        *
*                                             *
***********************************************

"""
        language_code = "en-US"
        
        return banner, language_code


def main():
    # now connect
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 22))
    except Exception as e:
        print("*** Bind failed: " + str(e))
        traceback.print_exc()
        sys.exit(1)

    
    sock.listen(100)
    print("Listening for connection ...")
    
    with open("shell_line.log" ,'a') as log:
        log.write("SERVER STARTS - %s \n" % str(datetime.now()))
        while True:
            try:    
                client, addr = sock.accept()
                print(addr)
            except Exception as e:
                print("*** Listen/accept failed: " + str(e))
                traceback.print_exc()
                sys.exit(1)

            print("Got a connection!")
            

            t = paramiko.Transport(client, gss_kex=False)
            t.set_gss_host(socket.getfqdn(""))
            t.banner_timeout = 60 
            print("Banner timeout: " + str(t.banner_timeout))
            try:
                t.load_server_moduli()
            except:
                print("(Failed to load moduli -- gex will be unsupported.)")
                raise
            t.add_server_key(host_key)
            server = Server()
            try:
                t.start_server(server=server)
            except paramiko.SSHException:
                print("*** SSH negotiation failed.")
                sys.exit(1)



            threat = threading.Thread(target=ssh_connection,
                            args=(t,server,log),
                            daemon=True
                            )
            threat.start()
        
        
def ssh_connection(t, server,log):
    print("ssh_connection, new thread alive!")
    # Wait for authentication and channel acceptance
    chan = t.accept(20)
    
    # Log the user and time
    if t.get_username() is not None:
        t.set_log_channel(t.get_username() + '::' + str(datetime.now()))
    else:
        t.set_log_channel("UNKNOWN_USERNAME" + '::' + str(datetime.now()))

    if chan is None:
        print("*** No channel.")
        sys.exit(1)
    
    log.write("Authenticated!" + "\n")
    print("Authenticated!")

    line = ""

    chan.send("\r\nPS C:\\Windows\\system32> ") 

    while True:

        if chan.closed:
            print("Session closed")
            break
        # Read one byte from the SSH channel
        character = chan.recv(1)

        if character in [b'\x7f', b'\x08']:  # Handling BACKSPACE or DELETE
            if len(line) > 0:
                # Remove the last character from the line buffer
                line = line[:-1]

                chan.send('\b \b')


        elif character == b'\r':  # When ENTER is pressed
            enter_pressed(chan,line)
            line = ""
        else:
            # If it's a regular character, add it to the line buffer
            line += character.decode('utf-8')  # Decode byte to string
            chan.send(character)  # Echo the character back to the terminal

        current_line = "peername=%s, time=%s, shell_line=%s" % (chan.getpeername(), str(datetime.now()), line)
        print(current_line)
        log.write(current_line + "\n")



        if b'exit' == line or b'\x03' == character:
            break
                

        

    chan.send('\r\nbye\r\n')

    chan.close()





#### Commands section ####


def enter_pressed(chan,line):
    chan.send("\n\r")  

    
    if not line:
        chan.send("PS C:\\Windows\\system32> ")  # Reprint the prompt
        return

    original_line = line.split()[0]
    command = original_line.lower()
    args = [arg.lower() for arg in line.split()[1:]]

    if command == 'whoami':
        whoami_command(chan)
    elif command == 'ipconfig':
        ipconfig_command(chan, args)   
    elif command == 'ls' or command == 'dir':
        ls_command(chan,args)     
    elif command == 'get-computerinfo':
        get_computerinfo_command(chan)      
    elif command == 'vssadmin' or command == 'vssadmin.exe' or command == 'c:\windows\system32\\vssadmin.exe':
        vssadmin_command(chan, args)  
    elif command == 'netsh' or command == 'netsh.exe' or command == 'c:\windows\system32\\netsh.exe':
        netsh_command(chan,args)   
    elif command == 'wmic' or command == 'wmic.exe' or command == 'c:\windows\system32\\wmic.exe':     
        wmic_command(chan, args)
    elif command == 'certutil' or command == 'certutil.exe' or command == 'c:\windows\system32\\certutil.exe':
        certutil_command(chan,args)   
    elif command == 'schtasks' or command == 'schtasks.exe' or command == 'c:\windows\system32\\schtasks.exe':
        schtasks_command(chan,args)
    elif line:
        not_recognized_command(chan,original_line)

    chan.send("PS C:\\Windows\\system32> ")  # Reprint the prompt


def remote_exec(chan,line):
    original_line = line.split()[0]
    command = original_line.lower()
    args = [arg.lower() for arg in line.split()[1:]]

    if command == 'whoami':
        whoami_command(chan)
    elif command == 'ipconfig':
        ipconfig_command(chan, args)   
    elif command == 'ls' or command == 'dir':
        ls_command(chan,args)     
    elif command == 'get-computerinfo':
        get_computerinfo_command(chan)      
    elif command == 'vssadmin' or command == 'vssadmin.exe' or command == 'c:\windows\system32\\vssadmin.exe':
        vssadmin_command(chan, args)  
    elif command == 'netsh' or command == 'netsh.exe' or command == 'c:\windows\system32\\netsh.exe':
        netsh_command(chan,args)   
    elif command == 'wmic' or command == 'wmic.exe' or command == 'c:\windows\system32\\wmic.exe':     
        wmic_command(chan, args)
    elif command == 'certutil' or command == 'certutil.exe' or command == 'c:\windows\system32\\certutil.exe':
        certutil_command(chan,args)   
    elif command == 'schtasks' or command == 'schtasks.exe' or command == 'c:\windows\system32\\schtasks.exe':
        schtasks_command(chan,args)
    elif line:
        not_recognized_command(chan,original_line)


def whoami_command(chan):
    chan.send('desktop-h5p88jg\janadm\r\n\r\n')


def ipconfig_command(chan, args):
    if not args:
        ip_config_info = (
            "\r\nWindows IP Configuration\r\n\r\n\r\n"
            "Ethernet adapter Ethernet:\r\n\r\n"
            "   Connection-specific DNS Suffix  . : corpnet.local\r\n"
            "   Link-local IPv6 Address . . . . . : fe80::1201:d101:8299:df9f%7\r\n"
            "   IPv4 Address. . . . . . . . . . . : 172.16.0.47\r\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n"
            "   Default Gateway . . . . . . . . . : 172.16.0.1\r\n\r\n"
        )
    elif args[0] == "/all":
        time_obtained = (datetime.now() - timedelta(days=1)).strftime("%A, %d %B %Y %H:%M:%S")
        time_expired = (datetime.now() + timedelta(days=1)).strftime("%A, %d %B %Y %H:%M:%S")
        ip_config_info = (
            "Windows IP Configuration\r\n\r\n"
            "   Host Name . . . . . . . . . . . . : DESKTOP-H5P88JG\r\n"
            "   Primary Dns Suffix  . . . . . . . :\r\n"
            "   Node Type . . . . . . . . . . . . : Hybrid\r\n"
            "   IP Routing Enabled. . . . . . . . : No\r\n"
            "   WINS Proxy Enabled. . . . . . . . : No\r\n"
            "   DNS Suffix Search List. . . . . . : corpnet.local\r\n\r\n"
            "Ethernet adapter Ethernet:\r\n\r\n"
            "   Connection-specific DNS Suffix  . : corpnet.local\r\n"
            "   Description . . . . . . . . . . . : HP Ethernet Adapter\r\n"
            "   Physical Address. . . . . . . . . : 94-F1-28-7A-C9-49\r\n"                         
            "   DHCP Enabled. . . . . . . . . . . : Yes\r\n"
            "   Autoconfiguration Enabled . . . . : Yes\r\n"
            "   Link-local IPv6 Address . . . . . : fe80::1201:d101:8299:df9f%7(Preferred)\r\n"
            "   IPv4 Address. . . . . . . . . . . : 172.16.0.47(Preferred)\r\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n"
            f"   Lease Obtained. . . . . . . . . . : {time_obtained}\r\n"        # CHANGE
            f"   Lease Expires . . . . . . . . . . : {time_expired}\r\n"      # CHANGE
            "   Default Gateway . . . . . . . . . : 172.16.0.1\r\n"
            "   DHCP Server . . . . . . . . . . . : 172.16.0.1\r\n"
            "   DHCPv6 IAID . . . . . . . . . . . : 112993297\r\n"
            "   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2E-20-A5-46-BC-24-11-7A-C9-49\r\n"
            "   DNS Servers . . . . . . . . . . . : 172.16.0.1\r\n"
            "                                       172.16.0.254\r\n"
            "   NetBIOS over Tcpip. . . . . . . . : Enabled\r\n\r\n"
        )
    else:
        ip_config_info = "\r\nError: unrecognized or incomplete command line.\r\n\r\n"

    chan.send(ip_config_info.encode())  


def ls_command(chan,args):
    windows_system32_output = (
'-a----        07.12.2019     10:09         145920 vssadmin.exe\r\n'
'-a----        15.05.2024     03:09        1674240 vssapi.dll\r\n'
'-a----        22.02.2024     23:10          70656 vsstrace.dll\r\n'
'-a----        15.05.2024     03:09        1495040 VSSVC.exe\r\n'
'-a----        22.02.2024     23:10          61952 vss_ps.dll\r\n'
'-a----        07.10.2024     00:45         522240 w32time.dll\r\n'
'-a----        07.12.2019     10:08         108032 w32tm.exe\r\n'
'-a----        22.02.2024     23:10          36352 w32topl.dll\r\n'
'-a----        07.10.2024     00:46         154624 WaaSAssessment.dll\r\n'
'-a----        07.10.2024     00:46         112640 WaaSMedicAgent.exe\r\n'
'-a----        07.10.2024     00:46         376832 WaaSMedicCapsule.dll\r\n'
'-a----        07.10.2024     00:46          29184 WaaSMedicPS.dll\r\n'
'-a----        07.10.2024     00:46         427520 WaaSMedicSvc.dll\r\n'
'-a----        07.12.2019     10:09          70144 WABSyncProvider.dll\r\n'
'-a----        07.12.2019     10:09          42496 waitfor.exe\r\n'
'-a----        07.12.2019     10:08          12800 WalletBackgroundServiceProxy.dll\r\n'
'-a----        07.12.2019     10:08         104960 WalletProxy.dll\r\n'
'-a----        15.05.2024     03:15         442368 WalletService.dll\r\n'
'-a----        15.05.2024     03:10          23552 WallpaperHost.exe\r\n'
'-a----        22.02.2024     23:12         265216 wavemsp.dll\r\n'
'-a----        22.02.2024     23:13         329728 wbadmin.exe\r\n'
'-a----        15.05.2024     03:08         561664 wbemcomn.dll\r\n'
'-a----        27.07.2024     18:09        1623552 wbengine.exe\r\n'
'-a----        15.05.2024     03:09         886272 wbiosrvc.dll\r\n'
'-a----        07.10.2024     00:46          27648 wci.dll\r\n'
'-a----        27.07.2024     18:06         137728 wcimage.dll\r\n'
'-a----        15.05.2024     03:08         156160 wcmapi.dll\r\n'
'-a----        15.05.2024     03:08         246272 wcmcsp.dll\r\n'
'-a----        15.05.2024     03:08         986112 wcmsvc.dll\r\n'
'-a----        22.02.2024     23:09         140288 WcnApi.dll\r\n'
'-a----        22.02.2024     23:09         483840 wcncsvc.dll\r\n'
'-a----        07.12.2019     10:08          39936 WcnEapAuthProxy.dll\r\n'
'-a----        07.12.2019     10:08          37376 WcnEapPeerProxy.dll\r\n'
'-a----        22.02.2024     23:09          49664 WcnNetsh.dll\r\n'
'-a----        15.05.2024     03:08         346624 wcnwiz.dll\r\n'
'-a----        27.07.2024     18:06         297984 wc_storage.dll\r\n'
'-a----        07.12.2019     10:09         739840 wdc.dll\r\n'
'-a----        07.12.2019     10:08         105472 wdi.dll\r\n'
'-a----        15.05.2024     03:10         276992 wdigest.dll\r\n'
'-a----        15.05.2024     03:08         260608 wdmaud.drv\r\n'
'-a----        22.02.2024     23:11         260064 wdscore.dll\r\n'
'-a----        07.12.2019     10:08            614 WdsUnattendTemplate.xml\r\n'
'-a----        07.12.2019     10:08           4608 WEB.rs\r\n'
'-a----        27.07.2024     18:06         527872 webauthn.dll\r\n'
'-a----        15.05.2024     03:14         992768 WebcamUi.dll\r\n'
'-a----        15.05.2024     03:13         270336 webcheck.dll\r\n'
'-a----        15.05.2024     03:13         236544 WebClnt.dll\r\n'
'-a----        22.02.2024     23:11         595456 webio.dll\r\n'
'-a----        09.10.2024     00:05        1234944 webplatstorageserver.dll\r\n'
'-a----        09.10.2024     00:04        2573824 WebRuntimeManager.dll\r\n'
'-a----        27.07.2024     18:06        1395080 webservices.dll\r\n'
'-a----        22.02.2024     23:11          47104 Websocket.dll\r\n'
'-a----        22.02.2024     23:12          81408 wecapi.dll\r\n'
'-a----        15.05.2024     03:13         245248 wecsvc.dll\r\n'
'-a----        22.02.2024     23:12         107008 wecutil.exe\r\n'
'-a----        07.12.2019     10:09          28672 wephostsvc.dll\r\n'
'-a----        09.10.2024     00:04         930376 wer.dll\r\n'
'-a----        15.05.2024     03:13         893952 werconcpl.dll\r\n'
'-a----        15.05.2024     03:13         132608 wercplsupport.dll\r\n'
'-a----        22.02.2024     23:11          47104 werdiagcontroller.dll\r\n'
'-a----        22.02.2024     23:11          25384 WerEnc.dll\r\n'
'-a----        15.05.2024     03:10         255136 weretw.dll\r\n'
'-a----        15.05.2024     03:10         577920 WerFault.exe\r\n'
'-a----        15.05.2024     03:10         180336 WerFaultSecure.exe\r\n'
'-a----        15.05.2024     03:10         237424 wermgr.exe\r\n'
'-a----        15.05.2024     03:10         254464 wersvc.dll\r\n'
'-a----        15.05.2024     03:13         256000 werui.dll\r\n'
'-a----        27.07.2024     18:06         405088 wevtapi.dll\r\n'
'-a----        15.05.2024     03:13         137216 wevtfwd.dll\r\n'
'-a----        07.10.2024     00:46        1882624 wevtsvc.dll\r\n'
'-a----        22.02.2024     23:10         248320 wevtutil.exe\r\n'
'-a----        07.12.2019     10:09         146944 wextract.exe\r\n'
'-a----        07.12.2019     10:08         115109 WF.msc\r\n'
'-a----        14.05.2024     12:36          25088 wfapigp.dll\r\n'
'-a----        22.02.2024     23:10          41472 wfdprov.dll\r\n'
'-a----        07.12.2019     10:08          72704 WFDSConMgr.dll\r\n'
'-a----        15.05.2024     03:08         677888 WFDSConMgrSvc.dll\r\n'
'-a----        22.02.2024     23:12          90624 WfHC.dll\r\n'
'-a----        15.05.2024     03:15         966656 WFS.exe\r\n'
'-a----        22.02.2024     23:13         669696 WFSR.dll\r\n'
'-a----        07.12.2019     10:08          61752 whealogr.dll\r\n'
'-a----        07.12.2019     10:09          43008 where.exe\r\n'
'-a----        07.12.2019     10:09          17920 whhelper.dll\r\n'
'-a----        07.12.2019     10:09          73728 whoami.exe\r\n'
'-a----        22.02.2024     23:12          98816 wiaacmgr.exe\r\n'
'-a----        15.05.2024     03:13         813056 wiaaut.dll\r\n'
'-a----        15.05.2024     03:13         253952 wiadefui.dll\r\n'
'-a----        15.05.2024     03:13         173056 wiadss.dll\r\n'
'-a----        07.12.2019     10:09          11776 WiaExtensionHost64.dll\r\n'
'-a----        27.07.2024     18:08         118272 wiarpc.dll\r\n'
'-a----        22.02.2024     23:12         102912 wiascanprofiles.dll\r\n'
'-a----        27.07.2024     18:08         782336 wiaservc.dll\r\n'
'-a----        22.02.2024     23:12          90624 wiashext.dll\r\n'
'-a----        27.07.2024     18:08          18944 wiatrace.dll\r\n'
'-a----        07.12.2019     10:09          38912 wiawow64.exe\r\n'
'-a----        27.07.2024     18:05         284160 WiFiCloudStore.dll\r\n'
'-a----        22.02.2024     23:10          41984 WiFiConfigSP.dll\r\n'
'-a----        15.05.2024     03:08          45568 wifidatacapabilityhandler.dll\r\n'
'-a----        15.05.2024     03:08         387584 WiFiDisplay.dll\r\n'
'-a----        15.05.2024     03:08         804864 wifinetworkmanager.dll\r\n'
'-a----        22.02.2024     23:09         133608 wifitask.exe\r\n'
'-a----        07.12.2019     10:08           2404 WimBootCompress.ini\r\n'
'-a----        22.02.2024     23:11         765808 wimgapi.dll\r\n'
'-a----        22.02.2024     23:11         523120 wimserv.exe\r\n'
'-a----        09.10.2024     00:04         142848 win32appinventorycsp.dll\r\n'
'-a----        15.05.2024     03:10         148960 Win32AppSettingsProvider.dll\r\n'
'-a----        09.10.2024     00:04         263680 Win32CompatibilityAppraiserCSP.dll\r\n'
'-a----        09.10.2024     00:03         598016 win32k.sys\r\n'
'-a----        09.10.2024     00:03        2917376 win32kbase.sys\r\n'
'-a----        09.10.2024     00:03        3807744 win32kfull.sys\r\n'
'-a----        15.05.2024     03:09          30208 win32kns.sys\r\n'
'-a----        15.05.2024     03:08        1337344 win32spl.dll\r\n'
'-a----        09.10.2024     00:03         133920 win32u.dll\r\n'
'-a----        22.02.2024     23:09          28672 Win32_DeviceGuard.dll\r\n'
'-a----        15.05.2024     03:09         183296 winbio.dll\r\n'
'-a----        15.05.2024     03:15         521728 WinBioDataModel.dll\r\n'
'-a----        15.05.2024     03:15          79360 WinBioDataModelOOBE.exe\r\n'
'-a----        15.05.2024     03:13          43520 winbioext.dll\r\n'
'-a----        15.05.2024     03:10         205232 winbrand.dll\r\n'
'-a----        07.10.2024     00:46         437248 wincorlib.dll\r\n'
'-a----        22.02.2024     23:12          44544 wincredprovider.dll\r\n'
'-a----        27.07.2024     18:06         216576 wincredui.dll\r\n'
'-a----        15.05.2024     03:09        1681920 WindowManagement.dll\r\n'
'-a----        15.05.2024     03:09         658640 WindowManagementAPI.dll\r\n'
'-a----        15.05.2024     03:08        1075200 Windows.AccountsControl.dll\r\n'
'-a----        09.04.2021     15:48        5729280 Windows.AI.MachineLearning.dll\r\n'
'-a----        22.02.2024     23:10         108544 Windows.AI.MachineLearning.Preview.dll      \r\n'
'-a----        15.05.2024     03:09         122880 Windows.ApplicationModel.Background.SystemEventsBroker.dll\r\n'
'-a----        22.02.2024     23:10          31232 Windows.ApplicationModel.Background.TimeBroker.dll\r\n'
'-a----        15.05.2024     03:08         781824 Windows.ApplicationModel.ConversationalAgent.dll\r\n'
'-a----        22.02.2024     23:09          73216 windows.applicationmodel.conversationalagent.internal.proxystub.dll\r\n'
'-a----        22.02.2024     23:09          89088 windows.applicationmodel.conversationalagent.proxystub.dll\r\n'
'-a----        15.05.2024     03:08         223744 Windows.ApplicationModel.Core.dll\r\n'
'-a----        27.07.2024     18:05         802288 windows.applicationmodel.datatransfer.dll   \r\n'
'-a----        07.10.2024     00:45         953976 Windows.ApplicationModel.dll\r\n'
'-a----        27.07.2024     18:06         494080 Windows.ApplicationModel.LockScreen.dll    \r\n'
'-a----        09.10.2024     00:03        2585856 Windows.ApplicationModel.Store.dll\r\n'
'-a----        15.05.2024     03:09         577024 Windows.ApplicationModel.Wallet.dll\r\n'
'-a----        09.10.2024     00:03        2500096 Windows.CloudStore.dll\r\n'
'-a----        27.07.2024     18:06         894464 Windows.CloudStore.Schema.DesktopShell.dll  \r\n'
'-a----        09.10.2024     00:03         861696 Windows.CloudStore.Schema.Shell.dll\r\n'
'-a----        07.10.2024     00:47         629760 Windows.Cortana.Desktop.dll\r\n'
'-a----        27.07.2024     18:06         366592 Windows.Cortana.OneCore.dll\r\n'
'-a----        27.07.2024     18:06         135168 Windows.Cortana.ProxyStub.dll\r\n'
'-a----        27.07.2024     18:06         536064 Windows.Data.Activities.dll\r\n'
'-a----        15.05.2024     03:08        6724608 Windows.Data.Pdf.dll\r\n'
'-a----        15.05.2024     03:08         647680 Windows.Devices.AllJoyn.dll\r\n'
'-a----        15.05.2024     03:08          90112 Windows.Devices.Background.dll\r\n'
'-a----        07.12.2019     10:08          20992 Windows.Devices.Background.ps.dll\r\n'
'-a----        15.05.2024     03:08        2314752 Windows.Devices.Bluetooth.dll\r\n'
'-a----        15.05.2024     03:08         100864 Windows.Devices.Custom.dll\r\n'
'-a----        07.12.2019     10:08          23552 Windows.Devices.Custom.ps.dll\r\n'
'-a----        07.10.2024     00:45         547128 Windows.Devices.Enumeration.dll\r\n'
'-a----        15.05.2024     03:08         190976 Windows.Devices.Haptics.dll\r\n'
'-a----        22.02.2024     23:10         288768 Windows.Devices.HumanInterfaceDevice.dll    \r\n'
'-a----        15.05.2024     03:09         392192 Windows.Devices.Lights.dll\r\n'
'-a----        22.02.2024     23:10         596992 Windows.Devices.LowLevel.dll\r\n'
'-a----        15.05.2024     03:08         437760 Windows.Devices.Midi.dll\r\n'
'-a----        15.05.2024     03:09        2339328 Windows.Devices.Perception.dll\r\n'
'-a----        15.05.2024     03:15         484352 Windows.Devices.Picker.dll\r\n'
'-a----        15.05.2024     03:09        2078208 Windows.Devices.PointOfService.dll\r\n'
'-a----        15.05.2024     03:11          54784 Windows.Devices.Portable.dll\r\n'
'-a----        22.02.2024     23:10         154112 Windows.Devices.Printers.dll\r\n'
'-a----        22.02.2024     23:11          45056 Windows.Devices.Printers.Extensions.dll     \r\n'
'-a----        15.05.2024     03:08         218624 Windows.Devices.Radios.dll\r\n'
'-a----        15.05.2024     03:13         219648 Windows.Devices.Scanners.dll\r\n'
'-a----        15.05.2024     03:11        1289216 Windows.Devices.Sensors.dll\r\n'
'-a----        22.02.2024     23:10         155136 Windows.Devices.SerialCommunication.dll     \r\n'
'-a----        15.05.2024     03:08         807424 Windows.Devices.SmartCards.dll\r\n'
'-a----        15.05.2024     03:09         567808 Windows.Devices.SmartCards.Phone.dll        \r\n'
'-a----        22.02.2024     23:10         424448 Windows.Devices.Usb.dll\r\n'
'-a----        15.05.2024     03:08         301568 Windows.Devices.WiFi.dll\r\n'
'-a----        22.02.2024     23:10         504832 Windows.Devices.WiFiDirect.dll\r\n'
'-a----        15.05.2024     03:08         199680 Windows.Energy.dll\r\n'
'-a----        09.10.2024     00:04         384512 Windows.FileExplorer.Common.dll\r\n'
'-a----        15.05.2024     03:08         916992 Windows.Gaming.Input.dll\r\n'
'-a----        15.05.2024     03:09         389120 Windows.Gaming.Preview.dll\r\n'
'-a----        15.05.2024     03:09          88064 Windows.Gaming.UI.GameBar.dll\r\n'
'-a----        22.02.2024     23:09         463360 Windows.Gaming.XboxLive.Storage.dll        \r\n'
'-a----        15.05.2024     03:08        1712128 Windows.Globalization.dll\r\n'
'-a----        22.02.2024     23:10          62976 Windows.Globalization.Fontgroups.dll        \r\n'
'-a----        15.05.2024     03:09         777728 Windows.Globalization.PhoneNumberFormatting.dll\r\n'
'-a----        15.05.2024     03:11         132776 Windows.Graphics.Display.BrightnessOverride.dll\r\n'
'-a----        15.05.2024     03:09         372576 Windows.Graphics.Display.DisplayEnhancementOverride.dll\r\n'
'-a----        15.05.2024     03:08         566664 Windows.Graphics.dll\r\n'
'-a----        15.05.2024     03:08        2308096 Windows.Graphics.Printing.3D.dll\r\n'
'-a----        15.05.2024     03:08         877568 Windows.Graphics.Printing.dll\r\n'
'-a----        07.10.2024     00:47        1253888 Windows.Graphics.Printing.Workflow.dll     \r\n'
'-a----        07.10.2024     00:47          19968 Windows.Graphics.Printing.Workflow.Native.dll\r\n'
'-a----        07.12.2019     10:09         158208 Windows.Help.Runtime.dll\r\n'
'-a----        09.10.2024     00:03         791040 windows.immersiveshell.serviceprovider.dll  \r\n'
'-a----        15.05.2024     03:10         133632 Windows.Internal.AdaptiveCards.XamlCardRenderer.dll\r\n'
'-a----        15.05.2024     03:08         546304 Windows.Internal.Bluetooth.dll\r\n'
'-a----        09.10.2024     00:04         230400 Windows.Internal.CapturePicker.Desktop.dll  \r\n'
'-a----        15.05.2024     03:10         174592 Windows.Internal.CapturePicker.dll\r\n'
'-a----        15.05.2024     03:08         299520 Windows.Internal.Devices.Sensors.dll        \r\n'
'-a----        15.05.2024     03:15         137216 Windows.Internal.Feedback.Analog.dll        \r\n'
'-a----        07.12.2019     16:12          24064 Windows.Internal.Feedback.Analog.ProxyStub.dll\r\n'
'-a----        15.05.2024     03:09         253440 Windows.Internal.Graphics.Display.DisplayColorManagement.dll\r\n'
'-a----        15.05.2024     03:09         170496 Windows.Internal.Graphics.Display.DisplayEnhancementManagement.dll\r\n'
'-a----        07.10.2024     00:47        1141760 Windows.Internal.Management.dll\r\n'
'-a----        15.05.2024     03:08         146432 Windows.Internal.Management.SecureAssessment.dll\r\n'
'-a----        15.05.2024     03:08          67072 Windows.Internal.PlatformExtension.DevicePickerExperience.dll\r\n'
'-a----        15.05.2024     03:13          56832 Windows.Internal.PlatformExtension.MiracastBannerExperience.dll\r\n'                                                
'-a----        15.05.2024     03:13         516608 Windows.Internal.PredictionUnit.dll\r\n'
'-a----        15.05.2024     03:13         158208 Windows.Internal.Security.Attestation.DeviceAttestation.dll\r\n'
'-a----        22.02.2024     23:12          48640 Windows.Internal.SecurityMitigationsBroker.dll\r\n'
'-a----        09.10.2024     00:04         914336 Windows.Internal.Shell.Broker.dll\r\n'
'-a----        15.05.2024     03:08          90112 windows.internal.shellcommon.AccountsControlExperience.dll\r\n'
'-a----        15.05.2024     03:08          61952 windows.internal.shellcommon.AppResolverModal.dll\r\n'
'-a----        09.10.2024     00:03         146224 Windows.Internal.ShellCommon.Broker.dll     \r\n'
'-a----        15.05.2024     03:10          41984 windows.internal.shellcommon.FilePickerExperienceMEM.dll\r\n'
'-a----        15.05.2024     03:10          41472 Windows.Internal.ShellCommon.PrintExperience.dll\r\n'
'-a----        15.05.2024     03:08         317440 windows.internal.shellcommon.shareexperience.dll\r\n'           
'-a----        15.05.2024     03:08          59392 windows.internal.shellcommon.TokenBrokerModal.dll\r\n'
)
    chan.send(windows_system32_output)
    windows_system32_output = (
'-a----        07.10.2024     00:45        1065472 Windows.Internal.Signals.dll\r\n'
'-a----        07.10.2024     00:45         258048 Windows.Internal.System.UserProfile.dll    \r\n'
'-a----        07.10.2024     00:46         188928 Windows.Internal.Taskbar.dll\r\n'
'-a----        07.12.2019     10:08          93696 Windows.Internal.UI.BioEnrollment.ProxyStub.dll\r\n'                                   
'-a----        07.12.2019     10:08         265216 Windows.Internal.UI.Logon.ProxyStub.dll     \r\n'
'-a----        15.05.2024     03:11         433152 Windows.Internal.UI.Shell.WindowTabManager.dll\r\n'                                        
'-a----        27.07.2024     18:05          71168 Windows.Management.EnrollmentStatusTracking.ConfigProvider.dll\r\n'                                       
'-a----        27.07.2024     18:05         301056 Windows.Management.InprocObjects.dll        \r\n'
'-a----        27.07.2024     18:05         111104 Windows.Management.ModernDeployment.ConfigProviders.dll\r\n'         
'-a----        22.02.2024     23:09          34304 Windows.Management.Provisioning.ProxyStub.dll\r\n'               
'-a----        15.05.2024     03:08         137216 Windows.Management.SecureAssessment.CfgProvider.dll\r\n'
'-a----        07.12.2019     16:12           6144 Windows.Management.SecureAssessment.Diagnostics.dll\r\n'                               
'-a----        27.07.2024     18:05         860672 Windows.Management.Service.dll\r\n'
'-a----        15.05.2024     03:08         254320 Windows.Management.Workplace.dll\r\n'
'-a----        22.02.2024     23:11          34304 Windows.Management.Workplace.WorkplaceSettings.dll\r\n'
'-a----        15.05.2024     03:14        1339904 Windows.Media.Audio.dll\r\n'
'-a----        15.05.2024     03:08         920576 Windows.Media.BackgroundMediaPlayback.dll   \r\n'
'-a----        22.02.2024     23:10          13824 Windows.Media.BackgroundPlayback.exe        \r\n'
'-a----        15.05.2024     03:08         593000 Windows.Media.Devices.dll\r\n'
'-a----        15.05.2024     03:14        7549296 Windows.Media.dll\r\n'
'-a----        22.02.2024     23:13        1393152 Windows.Media.Editing.dll\r\n'
'-a----        22.02.2024     23:10        1404416 Windows.Media.FaceAnalysis.dll\r\n'
'-a----        15.05.2024     03:08         791040 Windows.Media.Import.dll\r\n'
'-a----        15.05.2024     03:10         561480 Windows.Media.MediaControl.dll\r\n'
'-a----        15.05.2024     03:15        1071616 Windows.Media.MixedRealityCapture.dll       \r\n'
'-a----        15.05.2024     03:08        1044992 Windows.Media.Ocr.dll\r\n'
'-a----        15.05.2024     03:08         918528 Windows.Media.Playback.BackgroundMediaPlayer.dll\r\n'                                  
'-a----        15.05.2024     03:08         897024 Windows.Media.Playback.MediaPlayer.dll      \r\n'
'-a----        22.02.2024     23:10         113664 Windows.Media.Playback.ProxyStub.dll        \r\n'
'-a----        07.10.2024     00:45       10348448 Windows.Media.Protection.PlayReady.dll      \r\n'
'-a----        15.05.2024     03:14         117248 Windows.Media.Renewal.dll\r\n'
'-a----        27.07.2024     18:06        1885696 Windows.Media.Speech.dll\r\n'
'-a----        22.02.2024     23:10         568832 Windows.Media.Speech.UXRes.dll\r\n'
'-a----        15.05.2024     03:14        1135104 Windows.Media.Streaming.dll\r\n'
'-a----        07.12.2019     16:12         218624 Windows.Media.Streaming.ps.dll\r\n'
'-a----        15.05.2024     03:13        4374248 Windows.Mirage.dll\r\n'
'-a----        22.02.2024     23:13          59392 Windows.Mirage.Internal.Capture.Pipeline.ProxyStub.dll\r\n'
'-a----        15.05.2024     03:13         867328 Windows.Mirage.Internal.dll\r\n'
'-a----        15.05.2024     03:08         107008 Windows.Networking.BackgroundTransfer.BackgroundManagerPolicy.dll\r\n'
'-a----        22.02.2024     23:10         505856 Windows.Networking.BackgroundTransfer.ContentPrefetchTask.dll\r\n'                                               
'-a----        15.05.2024     03:08        1299968 Windows.Networking.BackgroundTransfer.dll   \r\n'
'-a----        27.07.2024     18:05         737280 Windows.Networking.Connectivity.dll\r\n'
'-a----        15.05.2024     03:08         937472 Windows.Networking.dll\r\n'
'-a----        22.02.2024     23:10         215552 Windows.Networking.HostName.dll\r\n'
'-a----        15.05.2024     03:09         399872 Windows.Networking.NetworkOperators.ESim.dll\r\n'                                               
'-a----        15.05.2024     03:08         143360 Windows.Networking.NetworkOperators.HotspotAuthentication.dll\r\n'
'-a----        22.02.2024     23:10         349184 Windows.Networking.Proximity.dll\r\n'
'-a----        22.02.2024     23:10         117760 Windows.Networking.ServiceDiscovery.Dnssd.dll\r\n'
'-a----        22.02.2024     23:10         148480 Windows.Networking.Sockets.PushEnabledApplication.dll\r\n'
'-a----        15.05.2024     03:09         631296 Windows.Networking.UX.EapRequestHandler.dll\r\n'
'-a----        15.05.2024     03:09        1523200 Windows.Networking.Vpn.dll\r\n'
'-a----        07.12.2019     10:09          75776 Windows.Networking.XboxLive.ProxyStub.dll   \r\n'
'-a----        15.05.2024     03:09         588800 Windows.Payments.dll\r\n'
'-a----        15.05.2024     03:08        1058344 Windows.Perception.Stub.dll\r\n'
'-a----        15.05.2024     03:09         269824 Windows.Security.Authentication.Identity.Provider.dll\r\n'
'-a----        15.05.2024     03:08         975872 Windows.Security.Authentication.OnlineId.dll\r\n'
'-a----        27.07.2024     18:05        1146368 Windows.Security.Authentication.Web.Core.dll\r\n'                  
'-a----        15.05.2024     03:08         115880 Windows.Security.Credentials.UI.CredentialPicker.dll\r\n'
'-a----        15.05.2024     03:08         143872 Windows.Security.Credentials.UI.UserConsentVerifier.dll\r\n'
'-a----        15.05.2024     03:08          99808 Windows.Security.Integrity.dll\r\n'
'-a----        09.10.2024     00:03        1205728 Windows.Services.TargetedContent.dll\r\n'
'-a----        15.05.2024     03:10         223744 Windows.SharedPC.AccountManager.dll\r\n'
'-a----        15.05.2024     03:09         161792 Windows.SharedPC.CredentialProvider.dll\r\n'
'-a----        27.07.2024     18:06         326656 Windows.Shell.BlueLightReduction.dll\r\n'
'-a----        15.05.2024     03:09          99840 Windows.Shell.ServiceHostBuilder.dll\r\n'
'-a----        07.12.2019     10:08          22528 Windows.Shell.StartLayoutPopulationEvents.dll\r\n'
'-a----        07.10.2024     00:46        5866024 Windows.StateRepository.dll\r\n'
'-a----        07.10.2024     00:46         118640 Windows.StateRepositoryBroker.dll\r\n'
'-a----        07.10.2024     00:46         250736 Windows.StateRepositoryClient.dll\r\n'
'-a----        07.10.2024     00:46          59464 Windows.StateRepositoryCore.dll\r\n'
'-a----        07.10.2024     00:46        1338872 Windows.StateRepositoryPS.dll\r\n'
'-a----        07.10.2024     00:46         268800 Windows.StateRepositoryUpgrade.dll\r\n'
'-a----        15.05.2024     03:08         410776 Windows.Storage.ApplicationData.dll\r\n'
'-a----        22.02.2024     23:10         182784 Windows.Storage.Compression.dll\r\n'
'-a----        09.10.2024     00:03        8050752 windows.storage.dll\r\n'
'-a----        15.05.2024     03:09         203264 Windows.Storage.OneCore.dll\r\n'
'-a----        27.07.2024     18:05         798720 Windows.Storage.Search.dll\r\n'
'-a----        15.05.2024     03:08         356352 Windows.System.Diagnostics.dll\r\n'
'-a----        15.05.2024     03:08          55808 Windows.System.Diagnostics.Telemetry.PlatformTelemetryClient.dll\r\n'                                    
'-a----        15.05.2024     03:08         107520 Windows.System.Diagnostics.TraceReporting.PlatformDiagnosticActions.dll\r\n'
'-a----        15.05.2024     03:08         756736 Windows.System.Launcher.dll\r\n'
'-a----        09.10.2024     00:05         150976 Windows.System.Profile.HardwareId.dll       \r\n'
'-a----        15.05.2024     03:08          72192 Windows.System.Profile.PlatformDiagnosticsAndUsageDataSettings.dll\r\n'
'-a----        15.05.2024     03:09         141312 Windows.System.Profile.RetailInfo.dll       \r\n'
'-a----        15.05.2024     03:08          62464 Windows.System.Profile.SystemId.dll\r\n'
'-a----        15.05.2024     03:08          54784 Windows.System.Profile.SystemManufacturers.dll\r\n'
'-a----        22.02.2024     23:10          23552 Windows.System.RemoteDesktop.dll\r\n'
'-a----        15.05.2024     03:08         322048 Windows.System.SystemManagement.dll        \r\n'
'-a----        15.05.2024     03:08          94208 Windows.System.UserDeviceAssociation.dll    \r\n'
'-a----        15.05.2024     03:08          65024 Windows.System.UserProfile.DiagnosticsSettings.dll\r\n'                                               
'-a----        15.05.2024     03:08         105472 Windows.UI.Accessibility.dll\r\n'
'-a----        09.10.2024     00:03         276480 Windows.UI.AppDefaults.dll\r\n'
'-a----        15.05.2024     03:15         363520 Windows.UI.BioFeedback.dll\r\n'
'-a----        15.05.2024     03:10         409088 Windows.UI.BlockedShutdown.dll\r\n'
'-a----        09.10.2024     00:03        1040896 Windows.UI.Core.TextInput.dll\r\n'
'-a----        15.05.2024     03:10        1591808 Windows.UI.Cred.dll\r\n'
'-a----        15.05.2024     03:10         326144 Windows.UI.CredDialogController.dll\r\n'
'-a----        15.05.2024     03:11        1310360 Windows.UI.dll\r\n'
'-a----        15.05.2024     03:10         274432 Windows.UI.FileExplorer.dll\r\n'
'-a----        15.05.2024     03:11        1256448 Windows.UI.Immersive.dll\r\n'
'-a----        07.12.2019     10:08        4511744 Windows.UI.Input.Inking.Analysis.dll\r\n'
'-a----        15.05.2024     03:09        1824256 Windows.UI.Input.Inking.dll\r\n'
'-a----        15.05.2024     03:08         199168 Windows.UI.Internal.Input.ExpressiveInput.dll\r\n'                        
'-a----        07.12.2019     10:08          84480 Windows.UI.Internal.Input.ExpressiveInput.Resource.dll\r\n'
'-a----        27.07.2024     18:06        3093504 Windows.UI.Logon.dll\r\n'
'-a----        15.05.2024     03:10          86016 Windows.UI.NetworkUXController.dll\r\n'
'-a----        15.05.2024     03:15        2744320 Windows.UI.PicturePassword.dll\r\n'
'-a----        15.05.2024     03:11         911872 Windows.UI.Search.dll\r\n'
'-a----        15.05.2024     03:15          41472 Windows.UI.Shell.dll\r\n'
'-a----        22.02.2024     23:10        1432064 Windows.UI.Shell.Internal.AdaptiveCards.dll \r\n'
'-a----        15.05.2024     03:08         141312 Windows.UI.Storage.dll\r\n'
'-a----        15.05.2024     03:08        4025344 Windows.UI.Xaml.Controls.dll\r\n'
'-a----        09.10.2024     00:03       17531904 Windows.UI.Xaml.dll\r\n'
'-a----        15.05.2024     03:08         974336 Windows.UI.Xaml.InkControls.dll\r\n'
'-a----        27.07.2024     18:05        1360896 Windows.UI.Xaml.Maps.dll\r\n'
'-a----        27.07.2024     18:05        1268224 Windows.UI.Xaml.Phone.dll\r\n'
'-a----        07.12.2019     10:08         706048 Windows.UI.Xaml.Resources.19h1.dll\r\n'
'-a----        07.10.2024     00:45          44032 Windows.UI.Xaml.Resources.Common.dll\r\n'
'-a----        07.12.2019     10:08         456704 Windows.UI.Xaml.Resources.rs1.dll\r\n'
'-a----        07.12.2019     10:08         508928 Windows.UI.Xaml.Resources.rs2.dll\r\n'
'-a----        07.12.2019     10:08         617472 Windows.UI.Xaml.Resources.rs3.dll\r\n'
'-a----        07.12.2019     10:08         645632 Windows.UI.Xaml.Resources.rs4.dll\r\n'
'-a----        07.12.2019     10:08         700928 Windows.UI.Xaml.Resources.rs5.dll\r\n'
'-a----        07.12.2019     10:08         301056 Windows.UI.Xaml.Resources.th.dll\r\n'
'-a----        07.12.2019     10:08         241664 Windows.UI.Xaml.Resources.win81.dll\r\n'
'-a----        07.12.2019     10:08         142336 Windows.UI.Xaml.Resources.win8rtm.dll\r\n'
'-a----        15.05.2024     03:15         210944 Windows.UI.XamlHost.dll\r\n'
'-a----        15.05.2024     03:09          65536 Windows.WARP.JITService.dll\r\n'
'-a----        15.05.2024     03:09          73216 Windows.WARP.JITService.exe\r\n'
'-a----        15.05.2024     03:08         235520 Windows.Web.Diagnostics.dll\r\n'
'-a----        15.05.2024     03:08         775168 Windows.Web.dll\r\n'
'-a----        15.05.2024     03:08        1514496 Windows.Web.Http.dll\r\n'
'-a----        15.05.2024     03:13          62464 WindowsActionDialog.exe\r\n'
'-a----        27.07.2024     18:05        1792824 WindowsCodecs.dll\r\n'
'-a----        22.02.2024     23:10         274944 WindowsCodecsExt.dll\r\n'
'-a----        22.02.2024     23:12       32610352 WindowsCodecsRaw.dll\r\n'
'-a----        07.12.2019     10:10           1649 WindowsCodecsRaw.txt\r\n'
'-a----        15.05.2024     03:09         126976 WindowsDefaultHeatProcessor.dll\r\n'
'-a----        15.05.2024     03:14          84960 windowsdefenderapplicationguardcsp.dll\r\n'
'-a----        15.05.2024     03:11         732160 WindowsInternal.ComposableShell.ComposerFramework.dll\r\n'
'-a----        15.05.2024     03:10         169472 WindowsInternal.ComposableShell.DesktopHosting.dll\r\n'
'-a----        15.05.2024     03:10          77312 WindowsInternal.Shell.CompUiActivation.dll\r\n'
'-a----        22.02.2024     23:12          22528 WindowsIoTCsp.dll\r\n'
'-a----        15.05.2024     03:11         290304 windowslivelogin.dll\r\n'
'-a----        27.07.2024     18:05          84240 WindowsManagementServiceWinRt.ProxyStub.dll\r\n'
'-a----        15.05.2024     03:10        1211904 windowsperformancerecordercontrol.dll\r\n'
'-a----        07.12.2019     10:08            759 WindowsSecurityIcon.png\r\n'
'-a----        09.10.2024     00:04        3025408 windowsudk.shellcommon.dll\r\n'
'-a----        07.10.2024     00:46          70656 WindowsUpdateElevatedInstaller.exe\r\n'
'-a----        22.02.2024     23:12          93184 winethc.dll\r\n'
'-a----        27.07.2024     18:09          31744 WinFax.dll\r\n'
'-a----        07.10.2024     00:47        1096192 winhttp.dll\r\n'
'-a----        22.02.2024     23:12         102912 winhttpcom.dll\r\n'
'-a----        15.05.2024     03:13         130048 WinHvEmulation.dll\r\n'
'-a----        15.05.2024     03:13         135168 WinHvPlatform.dll\r\n'
'-a----        07.10.2024     00:47        5045760 wininet.dll\r\n'
'-a----        07.12.2019     10:09          70144 wininetlui.dll\r\n'
'-a----        07.10.2024     00:47         420656 wininit.exe\r\n'
'-a----        07.10.2024     00:47          47600 wininitext.dll\r\n'
'-a----        09.10.2024     00:03         546304 winipcfile.dll\r\n'
'-a----        09.10.2024     00:03         929280 winipcsecproc.dll\r\n'
'-a----        22.02.2024     23:11         101888 winipsec.dll\r\n'
'-a----        07.12.2019     10:08         150528 winjson.dll\r\n'
'-a----        15.05.2024     03:09         190464 Winlangdb.dll\r\n'
'-a----        09.10.2024     00:04        1852408 winload.efi\r\n'
'-a----        09.10.2024     00:04        1574424 winload.exe\r\n'
'-a----        07.10.2024     00:47         904704 winlogon.exe\r\n'
'-a----        07.10.2024     00:47          86016 winlogonext.dll\r\n'
'-a----        22.02.2024     23:13        1771752 winmde.dll\r\n'
'-a----        07.12.2019     10:08          41472 winml.dll\r\n'
'-a----        22.02.2024     23:09         148376 winmm.dll\r\n'
'-a----        07.12.2019     10:08         144592 winmmbase.dll\r\n'
'-a----        09.10.2024     00:03        2398720 winmsipc.dll\r\n'
'-a----        22.02.2024     23:10          88064 WinMsoIrmProtector.dll\r\n'
'-a----        14.05.2024     12:37          19968 winnlsres.dll\r\n'
'-a----        22.02.2024     23:11          36808 winnsi.dll\r\n'
'-a----        22.02.2024     23:10          81920 WinOpcIrmProtector.dll\r\n'
'-a----        07.10.2024     00:47         549880 WinREAgent.dll\r\n'
'-a----        09.10.2024     00:04        1428240 winresume.efi\r\n'
'-a----        09.10.2024     00:04        1225336 winresume.exe\r\n'
'-a----        07.12.2019     10:08             33 winrm.cmd\r\n'
'-a----        07.12.2019     10:08         204074 winrm.vbs\r\n'
'-a----        22.02.2024     23:11          49152 winrnr.dll\r\n'
'-a----        07.12.2019     10:08          52736 winrs.exe\r\n'
'-a----        22.02.2024     23:11         122368 winrscmd.dll\r\n'
'-a----        07.12.2019     10:08          29184 winrshost.exe\r\n'
'-a----        07.12.2019     10:08           2048 winrsmgr.dll\r\n'
'-a----        07.12.2019     10:08          14848 winrssrv.dll\r\n'
'-a----        22.02.2024     23:10          20480 WinRTNetMUAHostServer.exe\r\n'
'-a----        22.02.2024     23:10         184832 WinRtTracing.dll\r\n'
'-a----        22.02.2024     23:12        2811392 WinSAT.exe\r\n'
'-a----        22.02.2024     23:12         377856 WinSATAPI.dll\r\n'
'-a----        22.02.2024     23:11         252928 WinSCard.dll\r\n'
'-a----        22.02.2024     23:11         390632 WinSetupUI.dll\r\n'
'-a----        22.02.2024     23:10          19968 winshfhc.dll\r\n'
'-a----        15.05.2024     03:10         334848 winsku.dll\r\n'
'-a----        22.02.2024     23:11          98304 winsockhc.dll\r\n'
'-a----        27.07.2024     18:05         651264 winspool.drv\r\n'
'-a----        15.05.2024     03:10        1070824 winsqlite3.dll\r\n'
'-a----        07.12.2019     10:09          26624 WINSRPC.DLL\r\n'
'-a----        07.12.2019     10:08          62976 winsrv.dll\r\n'
)    
    chan.send(windows_system32_output)
    windows_system32_output = (
        '-a----        22.02.2024     23:11         103424 winsrvext.dll\r\n'
'-a----        22.02.2024     23:11         353440 winsta.dll\r\n'
'-a----        07.12.2019     10:08         822272 WinSync.dll\r\n'
'-a----        07.12.2019     10:09         230400 WinSyncMetastore.dll\r\n'
'-a----        07.12.2019     10:09         136704 WinSyncProviders.dll\r\n'
'-a----        09.10.2024     00:03         423648 wintrust.dll\r\n'
'-a----        07.10.2024     00:46        1407992 WinTypes.dll\r\n'
'-a----        07.12.2019     10:08          29696 winusb.dll\r\n'
'-a----        07.12.2019     10:09          59392 winver.exe\r\n'
'-a----        22.02.2024     23:10          45568 WiredNetworkCSP.dll\r\n'
'-a----        15.05.2024     03:11         260096 wisp.dll\r\n'
'-a----        22.02.2024     23:11          37376 witnesswmiv2provider.dll\r\n'
'-a----        22.02.2024     23:11          92112 wkscli.dll\r\n'
'-a----        07.10.2024     00:48         290304 wkspbroker.exe\r\n'
'-a----        07.10.2024     00:48         140288 wkspbrokerAx.dll\r\n'
'-a----        07.10.2024     00:47         450560 wksprt.exe\r\n'
'-a----        07.12.2019     10:08          31744 wksprtPS.dll\r\n'
'-a----        27.07.2024     18:06         308224 wkssvc.dll\r\n'
'-a----        15.05.2024     03:08         471184 wlanapi.dll\r\n'
'-a----        22.02.2024     23:10         310784 wlancfg.dll\r\n'
'-a----        22.02.2024     23:11         588800 WLanConn.dll\r\n'
'-a----        22.02.2024     23:10         202240 wlandlg.dll\r\n'
'-a----        07.12.2019     10:08         103424 wlanext.exe\r\n'
'-a----        22.02.2024     23:10         394752 wlangpui.dll\r\n'
'-a----        22.02.2024     23:10         216064 WLanHC.dll\r\n'
'-a----        22.02.2024     23:10          16896 wlanhlp.dll\r\n'
'-a----        15.05.2024     03:09         755712 WlanMediaManager.dll\r\n'
'-a----        22.02.2024     23:12         400384 WlanMM.dll\r\n'
'-a----        15.05.2024     03:08         436224 wlanmsm.dll\r\n'
'-a----        22.02.2024     23:10         776704 wlanpref.dll\r\n'
'-a----        22.02.2024     23:10          69120 WlanRadioManager.dll\r\n'
'-a----        15.05.2024     03:08         481280 wlansec.dll\r\n'
'-a----        15.05.2024     03:08        2654208 wlansvc.dll\r\n'
'-a----        22.02.2024     23:10          36352 wlansvcpal.dll\r\n'
'-a----        22.02.2024     23:10         422400 wlanui.dll\r\n'
'-a----        07.12.2019     10:08           3584 wlanutil.dll\r\n'
'-a----        27.07.2024     18:06         356864 Wldap32.dll\r\n'
'-a----        07.10.2024     00:46         184504 wldp.dll\r\n'
'-a----        22.02.2024     23:10         122368 wlgpclnt.dll\r\n'
'-a----        15.05.2024     03:11         713728 wlidcli.dll\r\n'
'-a----        15.05.2024     03:11         300544 wlidcredprov.dll\r\n'
'-a----        22.02.2024     23:11         102400 wlidfdp.dll\r\n'
'-a----        22.02.2024     23:11          67072 wlidnsp.dll\r\n'
'-a----        15.05.2024     03:08         667136 wlidprov.dll\r\n'
'-a----        07.12.2019     10:08          30208 wlidres.dll\r\n'
'-a----        07.10.2024     00:45        2256896 wlidsvc.dll\r\n'
'-a----        22.02.2024     23:11          69264 wlrmdr.exe\r\n'
'-a----        22.02.2024     23:13         761392 WMADMOD.DLL\r\n'
'-a----        22.02.2024     23:13         745432 WMADMOE.DLL\r\n'
'-a----        15.05.2024     03:08        1820720 WMALFXGFXDSP.dll\r\n'
'-a----        07.12.2019     16:12         341904 WMASF.DLL\r\n'
'-a----        07.12.2019     16:12          14336 wmcodecdspps.dll\r\n'
'-a----        22.02.2024     23:13          40960 wmdmlog.dll\r\n'
'-a----        07.12.2019     16:12          95744 wmdmps.dll\r\n'
'-a----        07.12.2019     10:09           7680 wmdrmsdk.dll\r\n'
'-a----        06.12.2019     22:31           2560 wmerror.dll\r\n'
'-a----        07.12.2019     10:08           5632 wmi.dll\r\n'
'-a----        22.02.2024     23:09          49152 wmiclnt.dll\r\n'
'-a----        22.02.2024     23:09         361952 wmicmiplugin.dll\r\n'
'-a----        22.02.2024     23:11         176640 wmidcom.dll\r\n'
'-a----        22.02.2024     23:13         202752 wmidx.dll\r\n'
'-a----        07.12.2019     10:08         144673 WmiMgmt.msc\r\n'
'-a----        07.12.2019     10:09          31232 wmiprop.dll\r\n'
'-a----        07.12.2019     10:08         215552 wmitomi.dll\r\n'
'-a----        22.02.2024     23:13        1357312 WMNetMgr.dll\r\n'
'-a----        07.10.2024     00:49       11455488 wmp.dll\r\n'
'-a----        22.02.2024     23:13        1568256 WMPDMC.exe\r\n'
'-a----        07.12.2019     16:12         373248 WmpDui.dll\r\n'
'-a----        22.02.2024     23:13         221696 wmpdxm.dll\r\n'
'-a----        22.02.2024     23:13         312640 wmpeffects.dll\r\n'
'-a----        22.02.2024     23:10         381952 WMPhoto.dll\r\n'
'-a----        22.02.2024     23:13           2560 wmploc.DLL\r\n'
'-a----        07.10.2024     00:49         389536 wmpps.dll\r\n'
'-a----        22.02.2024     23:13         129024 wmpshell.dll\r\n'
'-a----        07.10.2024     00:47          20480 wmsgapi.dll\r\n'
'-a----        07.12.2019     10:08         993792 WMSPDMOD.DLL\r\n'
'-a----        22.02.2024     23:13        1253376 WMSPDMOE.DLL\r\n'
'-a----        22.02.2024     23:13        2454544 WMVCORE.DLL\r\n'
'-a----        22.02.2024     23:13        2524808 WMVDECOD.DLL\r\n'
'-a----        22.02.2024     23:13         214016 wmvdspa.dll\r\n'
'-a----        07.12.2019     16:12        2298600 WMVENCOD.DLL\r\n'
'-a----        07.12.2019     16:12         347096 WMVSDECD.DLL\r\n'
'-a----        07.12.2019     16:12         451584 WMVSENCD.DLL\r\n'
'-a----        22.02.2024     23:13         689664 WMVXENCD.DLL\r\n'
'-a----        07.12.2019     16:12          30720 WofTasks.dll\r\n'
'-a----        07.12.2019     10:08          36352 WofUtil.dll\r\n'
'-a----        09.10.2024     00:03          44032 WordBreakers.dll\r\n'
'-a----        07.10.2024     00:48         105472 WorkFolders.exe\r\n'
'-a----        15.05.2024     03:13         893952 WorkfoldersControl.dll\r\n'
'-a----        07.10.2024     00:48         109056 WorkFoldersGPExt.dll\r\n'
'-a----        07.12.2019     10:09          61952 WorkFoldersRes.dll\r\n'
'-a----        15.05.2024     03:13         230400 WorkFoldersShell.dll\r\n'
'-a----        15.05.2024     03:13        2233320 workfolderssvc.dll\r\n'
'-a----        07.10.2024     00:45         436224 wosc.dll\r\n'
'-a----        22.02.2024     23:10         354904 wow64.dll\r\n'
'-a----        22.02.2024     23:10          22464 wow64cpu.dll\r\n'
'-a----        22.02.2024     23:10         533152 wow64win.dll\r\n'
'-a----        22.02.2024     23:11          17920 wowreg32.exe\r\n'
'-a----        22.02.2024     23:09         452608 WpAXHolder.dll\r\n'
'-a----        07.12.2019     10:08         103424 wpbcreds.dll\r\n'
'-a----        15.05.2024     03:08        1651200 Wpc.dll\r\n'
'-a----        15.05.2024     03:08         336896 WpcApi.dll\r\n'
'-a----        07.12.2019     10:08          10143 wpcatltoast.png\r\n'
'-a----        07.10.2024     00:45        1869824 WpcDesktopMonSvc.dll\r\n'
'-a----        27.07.2024     18:05        1188048 WpcMon.exe\r\n'
'-a----        07.12.2019     10:08           4687 wpcmon.png\r\n'
'-a----        15.05.2024     03:08          40960 WpcProxyStubs.dll\r\n'
'-a----        27.07.2024     18:05        1050624 WpcRefreshTask.dll\r\n'
'-a----        27.07.2024     18:05         289280 WpcTok.exe\r\n'
'-a----        15.05.2024     03:08         859136 WpcWebFilter.dll\r\n'
'-a----        22.02.2024     23:13         101888 wpdbusenum.dll\r\n'
'-a----        07.10.2024     00:48         642560 wpdshext.dll\r\n'
'-a----        07.10.2024     00:48          30720 WPDShextAutoplay.exe\r\n'
'-a----        07.10.2024     00:48          67072 WPDShServiceObj.dll\r\n'
'-a----        15.05.2024     03:14         385024 WPDSp.dll\r\n'
'-a----        22.02.2024     23:13         230912 wpd_ci.dll\r\n'
'-a----        09.10.2024     00:03        1401344 wpnapps.dll\r\n'
'-a----        15.05.2024     03:09         368640 wpnclient.dll\r\n'
'-a----        27.07.2024     18:06        1507840 wpncore.dll\r\n'
'-a----        07.12.2019     10:08          24064 wpninprc.dll\r\n'
'-a----        22.02.2024     23:12          22528 wpnpinst.exe\r\n'
'-a----        15.05.2024     03:09         650752 wpnprv.dll\r\n'
'-a----        15.05.2024     03:09         245760 wpnservice.dll\r\n'
'-a----        07.12.2019     10:08          37888 wpnsruprov.dll\r\n'
'-a----        15.05.2024     03:09          86016 WpnUserService.dll\r\n'
'-a----        07.12.2019     10:08          14848 WpPortingLibrary.dll\r\n'
'-a----        07.12.2019     10:08          11776 WppRecorderUM.dll\r\n'
'-a----        07.12.2019     10:08            724 wpr.config.xml\r\n'
'-a----        15.05.2024     03:10         321024 wpr.exe\r\n'
'-a----        22.02.2024     23:11         176128 WPTaskScheduler.dll\r\n'
'-a----        27.07.2024     18:05        1329632 wpx.dll\r\n'
'-a----        06.12.2019     22:29          11264 write.exe\r\n'
'-a----        07.12.2019     10:08           4608 ws2help.dll\r\n'
'-a----        22.02.2024     23:11         429408 ws2_32.dll\r\n'
'-a----        22.02.2024     23:09           9216 wscadminui.exe\r\n'
'-a----        22.02.2024     23:09         299192 wscapi.dll\r\n'
'-a----        22.02.2024     23:12         223744 wscinterop.dll\r\n'
'-a----        22.02.2024     23:09          28160 wscisvif.dll\r\n'
'-a----        07.12.2019     10:08          13824 WSClient.dll\r\n'
'-a----        22.02.2024     23:11          95232 WSCollect.exe\r\n'
'-a----        22.02.2024     23:09          18944 wscproxystub.dll\r\n'
'-a----        27.07.2024     18:07         196608 wscript.exe\r\n'
'-a----        15.05.2024     03:08         354904 wscsvc.dll\r\n'
'-a----        22.02.2024     23:12          84992 wscui.cpl\r\n'
'-a----        15.05.2024     03:09         692736 WSDApi.dll\r\n'
'-a----        15.05.2024     03:13          57344 wsdchngr.dll\r\n'
'-a----        22.02.2024     23:12          92672 WSDPrintProxy.DLL\r\n'
'-a----        22.02.2024     23:10          24576 WsdProviderUtil.dll\r\n'
'-a----        22.02.2024     23:12          70656 WSDScanProxy.dll\r\n'
'-a----        22.02.2024     23:12         706048 wsecedit.dll\r\n'
'-a----        15.05.2024     03:11          89088 wsepno.dll\r\n'
'-a----        22.02.2024     23:10          64000 wshbth.dll\r\n'
'-a----        22.02.2024     23:11          25088 wshcon.dll\r\n'
'-a----        07.12.2019     10:08          23040 wshelper.dll\r\n'
'-a----        22.02.2024     23:11         103424 wshext.dll\r\n'
'-a----        22.02.2024     23:12          19768 wshhyperv.dll\r\n'
'-a----        22.02.2024     23:11          12800 wship6.dll\r\n'
'-a----        22.02.2024     23:11         147456 wshom.ocx\r\n'
'-a----        22.02.2024     23:10          20480 wshqos.dll\r\n'
'-a----        07.10.2024     00:47          18944 wshrm.dll\r\n'
'-a----        22.02.2024     23:11          12800 WSHTCPIP.DLL\r\n'
'-a----        07.12.2019     10:09          17560 wshunix.dll\r\n'
'-a----        27.07.2024     18:08         172544 wsl.exe\r\n'
'-a----        07.10.2024     00:48         291840 wslapi.dll\r\n'
'-a----        27.07.2024     18:08          91136 wslconfig.exe\r\n'
'-a----        22.02.2024     23:11          32768 WsmAgent.dll\r\n'
'-a----        07.12.2019     10:08           4675 wsmanconfig_schema.xml\r\n'
'-a----        22.02.2024     23:11          43008 WSManHTTPConfig.exe\r\n'
'-a----        22.02.2024     23:11          88576 WSManMigrationPlugin.dll\r\n'
'-a----        22.02.2024     23:11         180224 WsmAuto.dll\r\n'
'-a----        22.02.2024     23:11          16384 wsmplpxy.dll\r\n'
'-a----        22.02.2024     23:11          46592 wsmprovhost.exe\r\n'
'-a----        07.12.2019     10:08           1559 WsmPty.xsl\r\n'
'-a----        22.02.2024     23:11          61952 WsmRes.dll\r\n'
'-a----        15.05.2024     03:11        2812416 WsmSvc.dll\r\n'
'-a----        07.12.2019     10:08           2426 WsmTxt.xsl\r\n'
'-a----        22.02.2024     23:11         322048 WsmWmiPl.dll\r\n'
'-a----        07.12.2019     10:08          66048 wsnmp32.dll\r\n'
'-a----        07.12.2019     10:08          18944 wsock32.dll\r\n'
'-a----        07.12.2019     10:09          45568 wsplib.dll\r\n'
'-a----        09.10.2024     00:05        2024928 wsp_fs.dll\r\n'
'-a----        09.10.2024     00:05        1763336 wsp_health.dll\r\n'
'-a----        07.12.2019     10:09         965944 wsp_sr.dll\r\n'
'-a----        15.05.2024     03:10         120320 wsqmcons.exe\r\n'
'-a----        22.02.2024     23:11          94208 WSReset.exe\r\n'
'-a----        07.12.2019     10:09          95232 WSTPager.ax\r\n'
'-a----        22.02.2024     23:11          68368 wtsapi32.dll\r\n'
'-a----        27.07.2024     18:06         956416 wuapi.dll\r\n'
'-a----        22.02.2024     23:10          11264 wuapihost.exe\r\n'
'-a----        27.07.2024     18:06          66760 wuauclt.exe\r\n'
'-a----        07.10.2024     00:46        3431936 wuaueng.dll\r\n'
'-a----        15.05.2024     03:10         246784 wuceffects.dll\r\n'
'-a----        07.12.2019     10:08          51200 WUDFCoinstaller.dll\r\n'
'-a----        22.02.2024     23:11         161872 WUDFCompanionHost.exe\r\n'
'-a----        22.02.2024     23:11         270336 WUDFHost.exe\r\n'
'-a----        22.02.2024     23:11         196952 WUDFPlatform.dll\r\n'
'-a----        07.12.2019     10:09          55808 WudfSMCClassExt.dll\r\n'
'-a----        22.02.2024     23:11         595456 WUDFx.dll\r\n'
'-a----        15.05.2024     03:11         764968 WUDFx02000.dll\r\n'
'-a----        15.05.2024     03:11         127488 wudriver.dll\r\n'
'-a----        27.07.2024     18:06          85504 wups.dll\r\n'
'-a----        27.07.2024     18:06          64000 wups2.dll\r\n'
'-a----        15.05.2024     03:08         345088 wusa.exe\r\n'
'-a----        09.10.2024     00:04         541696 wuuhext.dll\r\n'
'-a----        15.05.2024     03:09         267776 wuuhosdeployment.dll\r\n'
'-a----        22.02.2024     23:12         580096 wvc.dll\r\n'
'-a----        15.05.2024     03:09         569344 WwaApi.dll\r\n'
'-a----        15.05.2024     03:11          40960 WwaExt.dll\r\n'
'-a----        15.05.2024     03:09         996224 WWAHost.exe\r\n'
'-a----        22.02.2024     23:09         579640 WWanAPI.dll\r\n'
'-a----        07.12.2019     10:09         105472 wwancfg.dll\r\n'
'-a----        15.05.2024     03:12         506880 wwanconn.dll\r\n'
'-a----        22.02.2024     23:12          73216 WWanHC.dll\r\n'
'-a----        15.05.2024     03:12         553472 wwanmm.dll\r\n'
'-a----        22.02.2024     23:12          52736 Wwanpref.dll\r\n'
'-a----        07.10.2024     00:45         112128 wwanprotdim.dll\r\n'
'-a----        15.05.2024     03:12          91648 WwanRadioManager.dll\r\n'
'-a----        07.10.2024     00:45        1517568 wwansvc.dll\r\n'
'-a----        22.02.2024     23:09          98792 wwapi.dll\r\n'
'-a----        15.05.2024     03:08         234496 XamlTileRender.dll\r\n'
'-a----        07.12.2019     10:08           3584 XAudio2_8.dll\r\n'
'-a----        15.05.2024     03:08         638976 XAudio2_9.dll\r\n'
'-a----        27.07.2024     18:05        1049088 XblAuthManager.dll\r\n'
'-a----        22.02.2024     23:09          93696 XblAuthManagerProxy.dll\r\n'
'-a----        15.05.2024     03:08         114688 XblAuthTokenBrokerExt.dll\r\n'
'-a----        15.05.2024     03:08        1291264 XblGameSave.dll\r\n'
'-a----        15.05.2024     03:08         159744 XblGameSaveExt.dll\r\n'
'-a----        07.12.2019     10:08          39936 XblGameSaveProxy.dll\r\n'
'-a----        15.05.2024     03:08          33792 XblGameSaveTask.exe\r\n'
'-a----        22.02.2024     23:09          70144 XboxGipRadioManager.dll\r\n'
'-a----        15.05.2024     03:08          72704 xboxgipsvc.dll\r\n'
'-a----        15.05.2024     03:08          84992 xboxgipsynthetic.dll\r\n'
'-a----        22.02.2024     23:12        1295360 XboxNetApiSvc.dll\r\n'
'-a----        07.12.2019     10:09          50688 xcopy.exe\r\n'
'-a----        22.02.2024     23:12          45568 XInput1_4.dll\r\n'
'-a----        07.12.2019     10:09          11264 XInput9_1_0.dll\r\n'
'-a----        15.05.2024     03:08          49664 XInputUap.dll\r\n'
'-a----        15.05.2024     03:11          70144 xmlfilter.dll\r\n'
'-a----        22.02.2024     23:11         216440 xmllite.dll\r\n'
'-a----        22.02.2024     23:11          22016 xmlprovi.dll\r\n'
'-a----        27.07.2024     18:08         109056 xolehlp.dll\r\n'
'-a----        15.05.2024     03:11         406016 XpsDocumentTargetPrint.dll\r\n'
'-a----        15.05.2024     03:11         456192 XpsGdiConverter.dll\r\n'
'-a----        15.05.2024     03:11        1515008 XpsPrint.dll\r\n'
'-a----        15.05.2024     03:11         379392 xpspushlayer.dll\r\n'
'-a----        22.02.2024     23:11         581120 XpsRasterService.dll\r\n'
'-a----        22.02.2024     23:11        2844672 xpsservices.dll\r\n'
'-a----        15.05.2024     03:11         268288 XpsToPclmConverter.dll\r\n'
'-a----        15.05.2024     03:11          78336 XpsToPwgrConverter.dll\r\n'
'-a----        07.12.2019     10:09           4014 xwizard.dtd\r\n'
'-a----        07.12.2019     10:09          64000 xwizard.exe\r\n'
    )    
    chan.send(windows_system32_output)


def get_computerinfo_command(chan):
    time_info = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    computer_info = (
    "\r\nWindows System Information\r\n\r\n"
    "WindowsBuildLabEx                                       : 19041.1.amd64fre.vb_release.191206-1406\r\n"
    "WindowsCurrentVersion                                   : 6.3\r\n"
    "WindowsEditionId                                        : Professional\r\n"
    "WindowsInstallationType                                 : Client\r\n"
    "WindowsInstallDateFromRegistry                          : 22.02.2023 19:40:58\r\n"
    "WindowsProductId                                        : 00330-80000-00000-AA400\r\n"
    "WindowsProductName                                      : Windows 10 Pro\r\n"
    "WindowsRegisteredOrganization                           :\r\n"
    "WindowsRegisteredOwner                                  : windows\r\n"
    "WindowsSystemRoot                                       : C:\\Windows\r\n"
    "WindowsVersion                                          : 2009\r\n"
    "BiosBIOSVersion                                         : {BOCHS  - 1}\r\n"
    "BiosCaption                                             : Default System BIOS\r\n"
    "BiosDescription                                         : Default System BIOS\r\n"
    "BiosManufacturer                                        :\r\n"
    "BiosName                                                : Default System BIOS\r\n"
    "BiosReleaseDate                                         : 01.04.2014 02:00:00\r\n"
    "CsCaption                                               : DESKTOP-H5P88JG\r\n"
    "CsCurrentTimeZone                                       : 120\r\n"
    "CsDomain                                                : WORKGROUP\r\n"
    "CsDomainRole                                            : StandaloneWorkstation\r\n"
    "CsManufacturer                                          : BOCHS_\r\n"
    "CsModel                                                 : BXPC____\r\n"
    "CsName                                                  : DESKTOP-H5P88JG\r\n"
    "CsNumberOfLogicalProcessors                             : 4\r\n"
    "CsNumberOfProcessors                                    : 2\r\n"
    "CsProcessors                                            : {AMD Ryzen 5 3600 (6 cores, 3.6 GHz)}\r\n"      
    "CsStatus                                                : OK\r\n"
    "OsName                                                  : Microsoft Windows 10 Pro\r\n"
    "OsVersion                                               : 10.0.19045\r\n"
    "OsSystemDrive                                           : C:\r\n"
    "OsWindowsDirectory                                      : C:\\Windows\r\n"
    "OsTotalPhysicalMemory                                   : 17179308032\r\n"
    "OsFreePhysicalMemory                                    : 13269668\r\n"
    "OsLocale                                                : pl-PL\r\n"
    f"OsLocalDateTime                                         : {time_info}\r\n"                     # CHANGE
    "OsLastBootUpTime                                        : 09.10.2024 00:34:10\r\n"
    "OsUptime                                                : 3.17:59:47.9056922\r\n"
    "OsRegisteredUser                                        : Janadm\r\n"
    "KeyboardLayout                                          : pl-PL\r\n"
    "LogonServer                                             : \\\\DESKTOP-H5P88JG\r\n"
    "PowerPlatformRole                                       : Desktop\r\n\r\n"
    ) 
    time.sleep(random.randint(2,6))
    chan.send(computer_info.encode())  


# Perhaps vssadmin resize shadowstorage add? -> https://blogs.vmware.com/security/2022/09/threat-report-illuminating-volume-shadow-deletion.html
def vssadmin_command(chan, args):
    if not args or len(args)<3:
        chan.send("vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\r\n(C) Copyright 2001-2013 Microsoft Corp.\r\n\r\nError: Invalid command.\r\n\r\n----- Commands Supported ----\r\n\r\nDelete Shadows        - Delete volume shadow copies\r\nList Providers        - List registered volume shadow copy providers\r\nList Shadows          - List existing volume shadow copies\r\nList ShadowStorage    - List volume shadow copy storage associations\r\nList Volumes          - List volumes eligible for shadow copies\r\nList Writers          - List subscribed volume shadow copy writers\r\nResize ShadowStorage  - Resize a volume shadow copy storage association\r\n\r\n")
    elif args[0] == 'delete' and args[1] == 'shadows' and args[2] == '/all':
        chan.send('vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool \r\n(C) Copyright 2001-2013 Microsoft Corp.')
        time.sleep(random.randint(2,6))
        chan.send('Successfully deleted 1 shadow copies. \r\n')
    elif args[0] == 'delete' and args[1] == 'shadows' and args[2] == '/all' and args[3] == '/quiet':
        chan.send('Successfully deleted 1 shadow copies. \r\n')
    elif args[0] == 'resize' and args[1] == 'shadowstorage' and args[2] == '/for=c:' and args[3] == '/on=c:' and  '/maxsize=' in args[4]:
        chan.send("vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\r\n")
        chan.send("(C) Copyright 2001-2013 Microsoft Corp.\r\n\r\n")
        time.sleep(random.randint(2,6))
        chan.send('Successfully resized the shadow copy storage association. \r\n\r\n')
    else:
        chan.send("vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool\r\n(C) Copyright 2001-2013 Microsoft Corp.\r\n\r\nError: Invalid command.\r\n\r\n----- Commands Supported ----\r\n\r\nDelete Shadows        - Delete volume shadow copies\r\nList Providers        - List registered volume shadow copy providers\r\nList Shadows          - List existing volume shadow copies\r\nList ShadowStorage    - List volume shadow copy storage associations\r\nList Volumes          - List volumes eligible for shadow copies\r\nList Writers          - List subscribed volume shadow copy writers\r\nResize ShadowStorage  - Resize a volume shadow copy storage association\r\n\r\n")


#https://htmlpreview.github.io/?https://github.com/MatthewDemaske/blogbackup/blob/master/netshell.html
#https://www.hackingarticles.in/windows-persistence-using-netsh/
def netsh_command(chan, args):
    if not args or len(args) <= 2:
        input_error = (
    "The syntax supplied for this command is not valid. Check help for the correct syntax.\r\n\r\n"
    "Usage: add helper <DllFileName>\r\n\r\n"
    "Remarks:\r\n"
    "       Installs the specified helper DLL in netsh.\r\n\r\n"
    "Example:\r\n"
    "       add helper ipmontr.dll\r\n\r\n"
    "       The above command installs ipmontr.dll in netsh.\r\n"
    )
        chan.send(input_error)
    elif args[0] == 'add' and args[1] == 'helper' and args[2].endswith('.dll'):
        chan.send('Ok.\r\n')
    elif args[0] == 'add' and args[1] == 'helper' and not args[2].endswith('.dll'):
        chan.send('The following helper DLL cannot be loaded: ' + args[2] + '.\r\n\r\n')   



#https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/
#https://www.hackingarticles.in/windows-exploitation-wmic/
#https://lolbas-project.github.io/lolbas/Binaries/Wmic/
def wmic_command(chan, args):
    if not args or len(args) <= 3:
        chan.send('wmic:root\\cli> ')
        time.sleep(random.randint(1,3))
        chan.send('\r\n')
    elif args[0] == 'process' and args[1] == 'call' and args[2] == 'create' and args[3]:
        process_id = random.randint(1000, 9999)
        process_creation_success = (
            f'Executing (Win32_Process)->Create() \r\n'
            'Method execution successful.\r\n'
            'Out Parameters:\r\n'
            'instance of __PARAMETERS\r\n'
            '{\r\n'
            f'    ProcessId = {process_id};\r\n'
            '    ReturnValue = 0;\r\n'
            '};\r\n\r\n'
        )
        chan.send(process_creation_success)
    elif args[0].startswith('/node:') and args[1] == 'process' and args[2] == 'calls' and args[3] == 'create':
        process_id = random.randint(1000, 9999)
        process_creation_success = (
            f'Executing (Win32_Process)->Create() \r\n'
            'Method execution successful.\r\n'
            'Out Parameters:\r\n'
            'instance of __PARAMETERS\r\n'
            '{\r\n'
            f'    ProcessId = {process_id};\r\n'
            '    ReturnValue = 0;\r\n'
            '};\r\n\r\n'
        )
        chan.send(process_creation_success)
    elif args[0] == 'process' and args[1] == 'get' and args[2] == 'brief' and args[3].startswith('/format:'): 
        invalid_xsl_format = (
            'Node - DESKTOP-H5P88JG\r\n'
            'ERROR:\r\n'
            'Description = Invalid query\r\n'
            'Invalid XSL format (or) file name.\r\n'
        )   
        chan.send(invalid_xsl_format)
    elif len(args)>4 and  args[0] == 'datafile' and args[1] == 'where' and args[2].startswith('"name=') and args[3] == 'call' and args[4] == 'copy':
        copy_success = (
            'Executing (\\DESKTOP-H5P88JG\ROOT\CIMV2:CIM_DataFile.Name->Copy() \r\n'
            'Method execution successful.\r\n'
            'Out Parameters:\r\n'
            'instance of __PARAMETERS\r\n'
            '{\r\n'
            '    ReturnValue = 0;\r\n'              ## 0 indicates success in this case
            '};\r\n\r\n'
        )
        chan.send(copy_success)
    else:
        chan.send(' - Alias not found.\r\n\r\n')




#https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
def certutil_command(chan,args):
    if not args:
        certutil_info = ("CertUtil: -dump command completed successfully.\r\n\r\n")
        chan.send(certutil_info)
    elif "help" in args[0]:
        certutil_info = (
            "CertUtil: Unknown arg: --help\r\n\r\n"
            "CertUtil -?              -- Display a verb list (command list)\r\n"
            "CertUtil -dump -?        -- Display help text for the \"dump\" verb\r\n"
            "CertUtil -v -?           -- Display all help text for all verbs\r\n"
        )
        chan.send(certutil_info)
    elif len(args) >=3 and args[0] == "-urlcache" and args[1] == "-split" and args[2] == "-f" and args[3]:
        certutil_info = (
            "****  Online  ****\r\n"
            "   000000  ...\r\n"
            "   1514ce\r\n"
            "CertUtil: -URLCache command completed successfully.\r\n\r\n"
        )
        chan.send(certutil_info)
    elif len(args) >=3 and args[0] == "-verifyctl" and args[1] == "-f" and args[2] == "-split" and args[3]:    
        certutil_info = (
            "CertUtil -verifyCTL command FAILED 0x800931b (ASN: 267 CRYPT_E_ASN1_BADTAG)\r\n"
            "CertUtil: ASN1 - bad tag value.\r\n"
        )
        chan.send(certutil_info)
    elif len(args) >=4 and args[0] == "-urlcache" and args[1] == "-split" and args[2] == "-f" and args[3] and ":" in args[4]:
                certutil_info = (
            "****  Online  ****\r\n"
            "   000000  ...\r\n"
            "   0016\r\n"
            "CertUtil: -URLCache command completed successfully.\r\n\r\n"
        )
    elif args[0] == "-encode" and args[1] and args[2]:
        input_length = random.randint(120000,1321000)
        output_length = input_length + random.randint(500,700)
        certutil_info = (
            f"Input Length = {input_length}\r\n"
            f"Output Length = {output_length}\r\n"
            "CertUtil: -encode command completed successfully.\r\n\r\n"
        )
        chan.send(certutil_info)
    elif args[0] == "-decode" and args[1] and args[2]:
        input_length = random.randint(120000,1321000)
        output_length = input_length - random.randint(600,700)
        certutil_info = (
            f"Input Length = {input_length}\r\n"
            f"Output Length = {output_length}\r\n"
            "CertUtil: -decode command completed successfully.\r\n\r\n"
        )
        chan.send(certutil_info)
    elif args[0] == "-decodehex" and args[1] and args[2]:
        input_length = random.randint(123444,1721000)
        output_length = input_length - random.randint(800,960)
        certutil_info = (
            f"Input Length = {input_length}\r\n"
            f"Output Length = {output_length}\r\n"
            "CertUtil: -decodehex command completed successfully.\r\n\r\n"
        )
        chan.send(certutil_info)
    else: 
        certutil_info=(
            "CertUtil: -dump command failed 0x80070002 (WIN32: 2 ERROR_FILE_NOT_FOUND)\r\n"
            "CertUtil: Nie można odnaleźć określonego pliku.\r\n"
        )
        chan.send(certutil_info)    



def schtasks_command(chan,args):
    name_of_task = ""
    if not args:
        chan.send("Odmowa dostępu.\r\n\r\n")
        return
    for arg in args:
        if arg == "/tn":
            name_of_task = args[args.index(arg) + 1]
    if args[0] == "/create":
        schtasks_info = (
        f"SUCCESS: The scheduled task \"{name_of_task} \" has successfully been created.\r\n"
        ) 
        chan.send(schtasks_info)
    else:
        schtasks_info = (
            "ERROR: Invalid argument/option.\r\n"
            "Type \"SCHTASKS /QUERY /?\" for usage.\r\n"
        )
        chan.send(schtasks_info)    
        


def not_recognized_command(chan,command):
    chan.send('\'' + command + '\' is not recognized as an internal or external command, operable program or batch file.\r\n\r\n')

if __name__ == "__main__":
    main()



