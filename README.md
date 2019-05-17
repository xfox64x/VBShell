# VBShell
Reverse VBS C2

## Summary
A reverse VBS C2 client/server I tried to minimize for use with Ducky/Jackit and other limited enagements. Things have changed significantly: 
* VbsServer (Python 3) - Listens for the client callbacks, handles staging, and tracks client tasking.
* VbsClientStage1 (VBS) - Does initial callback and executes whatever VBS its handed (usually the second-stage).
* VbsClientStage2 (VBS) - The second-stage, with more advanced capabilities:
  * Commands are now BYO via dynamic global execution. Define functions and set variables in separate VBScripts, add their paths to the global tasking files, and watch execution happen.
* WpadProxyDemo (VBS) - Demonstrates how to resolve a proxy from the WPAD server (for getting out through proxies).

Start the python multi-threaded VbsServer and let the client script rip. Based on a number of other VBS shells out there.

## The Plan
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

## Findings
The stock Crazyradio PA can't penetrate the target building's exterior - I haven't tried to see how close I can get, but at a distance of about 15 meters from a user I can clearly see using a vulnerable Logitech mouse, the radio seems unable to pick up a signal through the glass walls (walls not specifically designed to interfere with signals). Upon reading numerous posts about interference-based range issues with unshielded NRF24L01 modules, I'm planning on shielding the PCB and filtering the USB power source. 1,000 meters of LOS drone communication should be good for at least 15 meters through glass, right? Update: covered the module in many layers of plastic wrap, followed by tinfoil, to keep the breakaway government, clockwork elves, and extra signals away from the LNA (attempting to ground it on the grounding points). This seems to have significantly improved device detection, identifying my test device from ~20 meters, through my car, garage, house, and two closed doors, though I couldnt be bothered to set up actual tests proving any of this.

The way I design, write, and code these projects is terrible. My second-stage client enables global, dynamic execution, and instead of concentrating on dynamically modifying the global environment, by changing variables and adding functions through this idea of "tasking", I put a ton of time into parsing text on the client's side. You would think that I would know by now that the best solutions require the least static concepts, but I'm dumb. Changes to follow. Also: Using Jackit as a starting point for the Mousejack side of the project was a mistake. I ended up ripping almost everything up to kluge the functionality of the scripts together and automate a sensible attack plan (attacking everything, only once, immediately after channel/HID identification and a successful ping). Both sides still aren't fully integrated, though they exist as one massive blob of differently-formatted spaghetti.

Security products suck. Symantec ate my VBS lunch; Crowdstrike couldn't care less. I originally thought Symantec was doing some runtime dynamic analysis on the calls I was making or how things were done. The first-stage flagged as ISB.Downloader!gen40, when written to disk. Cool. Tried calling the first-stage from a share, I saw it callback and pick up the second-stage, but then Symantec killed it with fire. The download-and-execute logic must be too aparent. Obfuscation did nothing. One answer was an overly complicated PowerShell one-liner, calling Invoke-WebRequest, after applying both certificate and header fixes, to download the first-stage VBS and then execute it on command line; it is a massive payload to type (and sit through). I thought Symantec might even be catching the same logic in the second-stage payload, somehow. Having success with this PS payload made me question all of this, so I added a bit of the second to the first, adding a bullshit regex that captures all of the text and calling Execute on the first resulting submatch. This was, apparently, enough. If one can fix the SSL and header issues between PowerShell and the Python server, one could create a smaller, proxy-aware payload that would be far more effective.

## Recent Changes
* SSL w/ self-signed certs is now supported.
* Automated tasking is a thing, though undocumented.
* Stages are now templates with dynamic values and are automatically deployed/generated.
* Request paths have been randomized and sveral checks were added to make blue-team analysis more difficult.

## TODO
INSTALL isn't really functional, right now. Creating effective tasking, automating the public share creation, and linking the Jackit on the local PI with the VbsServer on the AWS instance will probably net great increases in speed and effectiveness - put Jackit on auto-pwn and do the superquick wscript execution from a public share. Writing binary files to the client host isn't supported. The different stages and URI paths could probably be obfuscated and customized per each attempted Jackit compromise.
