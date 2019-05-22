Set Shell = CreateObject("WScript.Shell")
Set objLocator = CreateObject("WbemScripting.SWbemLocator")
Set objService = objLocator.ConnectServer(".", "root\cimv2")
Results = "[+] Windows Product ID(s):" & VBNewLine
For each product in objService.ExecQuery("SELECT * FROM Win32_ComputerSystemProduct")
	Results = Results & vbTab & product.UUID & VBNewLine
Next

IsLaptop = False
For each objItem in objWMIService.ExecQuery("Select * from Win32_Battery")
	IsLaptop = True
Next
If IsLaptop Then
	Results = Results & vbNewLine & "[+] Device is a laptop." & vbNewLine
Else
	Results = Results & vbNewLine & "[+] Device is NOT a laptop." & vbNewLine
End If

Set objNetwork = CreateObject("Wscript.Network")
Set objSysInfo = CreateObject("ADSystemInfo")

Results = Results & vbNewLine & "[+] Current User: " & objNetwork.UserName & vbNewLine
Results = Results & vbNewLine & "[+] Current User's DN: " & objSysInfo.UserName & vbNewLine
