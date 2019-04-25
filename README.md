# VBShell
Reverse VBS Shell Client and Server

## Summary
An example reverse VBS shell I tried to minimize, for use with Ducky/Jackit and other limited enagements. The three pieces here: 
* VbsServer (Python 3) that listens for client callbacks and provides shell access.
* VbsClient (VBS) script that does the callbacks and execution.
* VbsClientMinimizedDuckScript (USBRubberDucky script) which is the client script, but formatted for Ducky/Jackit use.
* VbsClientFromShareDuckScript (USBRubberDucky script) a much faster Ducky/Jackit script that runs cscript on a copy of the VbsClient that you're sharing from a remote Windows file share.

Start the python multi-threaded VbsServer and let the client script rip. Based on a number of other VBS shells out there.

## TODO
* Replace the interactive shell with some sort of automated tasking logic.
