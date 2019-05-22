WScript.Echo "You've been hacked."
Set objShell = CreateObject("WScript.Shell" )
appDataLocation=objShell.ExpandEnvironmentStrings("%APPDATA%")
WriteFile appDataLocation & "\Mozilla\asdf.txt", "asdfasdfasdfasdfasdfasdfsaasdf"
Break = True
