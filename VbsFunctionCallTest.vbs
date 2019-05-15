WScript.Echo "Calling function: WriteFile"
Set objShell = CreateObject("WScript.Shell" )
appDataLocation=objShell.ExpandEnvironmentStrings("%APPDATA%")
WriteFile appDataLocation & "\Mozilla\asdf.txt", "asdfasdfasdfasdfasdfasdfsaasdf"
Break = True
