# VBShell
Reverse VBS C2

## Summary
A reverse VBS C2 client/server I tried to minimize for use with Ducky/Jackit and other limited enagements. Things have changed significantly: 
* VbsServer (Python 3) - Listens for the client callbacks, handles staging, and tracks client tasking.
* VbsClientStage1 (VBS) - Does initial callback and executes whatever VBS its handed (usually the second-stage).
* VbsClientStage2 (VBS) - The second-stage, with more advanced capabilities:
  * Terminate the remote client:
    * EXIT
  * Set the remote client's ID (already automated - use at own risk): 
    * SETUUID \<uuid\>
  * Change script's random callback intervals: 
    * SETCALLBACK INTERVAL:\<milliseconds_to_sleep\> RANGE:\<max_milliseconds_to_deviate\>
  * Change callback destination: 
    * SETCALLBACKHOST HOST:\<new_host\> PORT:\<new_port\>
  * Dynamic VBS Execution: 
    * EXECVBS \<vbscript\>
  * Write text files out to host: 
    * WRITEFILE FILEPATH:\<unquoted_file_path\> FILECONTENT:\<text_to_write\>
  * Execute commands in cmd (pops a cmd window users can see): 
    * CMD \<windows_commands\>
  * Siliently execute commands (without standard out/error return values): 
    * SILENTCMD \<windows_commands\>
  * Install the VbsClient as a scheduled task (not fully functional):
    * INSTALL
* WpadProxyDemo (VBS) - Demonstrates how to resolve a proxy from the WPAD server (for getting out through proxies).
* SecondStageTest.htm (VBS) - Used to test stage-one getting through a proxy, with SSL, to https://raw.githubusercontent.com/xfox64x/VBShell/master/SecondStageTest.htm

Start the python multi-threaded VbsServer and let the client script rip. Based on a number of other VBS shells out there.

The plan behind all of this is that I'm going to:
1. Set up my yagi antenna and Jackit-CrazyRadio-Pi unit in the backseat of my car.
2. Drive up into the engagement's scenic roundabout entrance.
3. Point the antenna at some unsuspecting fools.
4. Inject the first-stage VBS payload into someone's stream (cross fingers for speed).
5. Catch the callback on an external AWS instance.
6. Upload the second-stage VBS payload.
7. Write a copy of an obfuscated second-stage payload (with the new client's correct UUID) to the client.
8. Schedule a task to run said local obfuscated payload every couple of hours.
9. EXIT out of the initial payloads, and wait for the next callback.
10. Create a public share on the first compromised host, sharing the first-stage payload, to speed up additional attacks.
11. ?????
12. PROFIT!!!!!

Of course, I have permission to do all of this during my red-team engagements, so don't be goin around doin anything *illegal*, you hear?

## Recent Changes
* SSL w/ self-signed certs is now supported.
* Automated tasking is a thing, though undocumented.
* Stages are now templates with dynamic values and are automatically deployed/generated.
* Request paths have been randomized and sveral checks were added to make blue-team analysis more difficult.

## TODO
INSTALL isn't really functional, right now. Creating effective tasking, automating the public share creation, and linking the Jackit on the local PI with the VbsServer on the AWS instance will probably net great increases in speed and effectiveness - put Jackit on auto-pwn and do the superquick wscript execution from a public share. Writing binary files to the client host isn't supported. The different stages and URI paths could probably be obfuscated and customized per each attempted Jackit compromise.
