# VBShell
Mousejack attack and reverse VBS C2 script.

## Summary
I smashed a keystroke-injection-attack script and reverse VBS C2 client/server together for use during limited on-site enagements. The overall goal was to leverage the Mousejack attack to gain an initial foothold, with minimal attacker interaction, bypassing both CrowdStrike's and Symantec Endpoint Protection's detection capabilities.

For some odd reason, this was sort of based on [jackit](https://github.com/insecurityofthings/jackit), which uses the findings of [Bastille's Mousejack](https://github.com/BastilleResearch/mousejack) research.

## Requirements
Python 3.6+ is required because the updated/fixed SSL functionality is required. Here's a guide by @SeppPenner on building and installing Python 3.7.0 on Raspbian: https://gist.github.com/SeppPenner/6a5a30ebc8f79936fa136c524417761d

If you are considering using their install script, I recommend removing the lines that delete the python source/zip (lines 10-11) and uninstall the dependencies (line 12-14) until you are completely sure the build and install went OK. You will also probably need build-essential some times in the future, so maybe don't run those last lines...

A CrazyRadio dongle with the custom Mousejack firmware is required: https://github.com/BastilleResearch/mousejack

PyUSB (python -m pip install pyusb)

All other external dependencies have been eliminated.

## The Plan
My plan was to:
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

The humans are very aware. In a recent test, only 3 out of ~25 were successfully pwnt, where the second-stage payloads successfully executed tasking (profiling the user and host). In order for a keystroke-injection-attack to be successful, the users need to be actively NOT using their machines, or else they will most likely click out of the command prompt being written to or add additional keystrokes to the carefully formatted payloads. This was the number one reason why these attacks failed, based on visual surveillance. The second most likely reason for failure is locked screens. In these cases, the duck payloads actually resulted in numerous AD account lockouts because the keystrokes end up in the password feild and the enter button is pressed numerous times. Beyond that, almost every one of those ~25 people complained about a strange command prompt popup and one even gave me the finger. The 3 successes took place between a trio of people talking to each other, instead of working on their computers. Injection takes too long, though I guess I only need one successful deployment to then create an internal network share I can put more first-stage VBS payloads on. The attack would then be as quick as typing the path to the remotely shared resource in the run prompt.

Practically, not much can be done to stop this attack beyond ditching the vulnerable devices. I wanted to attack each device, only once, immediately after verifying its current channel. This would result in the most accurate and successful attacks, while respecting the target users' integrity; everyone's working and I don't want to overwhelmingly interefere with their day. That being said, I could also just sit there and attack a device until I wear down the user enough for a successful execution. They can't really stop it, beyond locking their machines, disconnecting the devices, and walking away - creating a DoS of a different type; good luck finding me.

## TODO
Add logic and tasking to create an internal share, upload first-stage payloads to said share, and inject attacks that execute the shared payloads (would be much faster and less noticeable).
