' Finds the hosts's proxy via WPAD, and adds it to the XMLHTTP server.
' There are probably few instances where this is useful, though I happen to be in one.
' Most other proxied situations can be triaged in the registry.

ComputerDomain = ""
Set xHttp = CreateObject("MSXML2.ServerXMLHTTP.6.0")
xHttp.setOption 2, SXH_SERVER_CERT_IGNORE_ALL_SERVER_ERRORS
Set objWMISvc = GetObject( "winmgmts:\\.\root\cimv2" )
Set colItems = objWMISvc.ExecQuery( "Select * from Win32_ComputerSystem" )
For Each objItem in colItems
    If objItem.PartOfDomain Then
        ComputerDomain = objItem.Domain
    End If
Next
If Len(ComputerDomain) > 0 Then
    xHttp.Open "GET", "https://wpad." & ComputerDomain & "/wpad.dat", False
    xHttp.send
    Set ProxyRe = New RegExp
    ProxyRe.pattern = "PROXY\s+[^,~:!@#$%^&'\(\)\{\}_ ]+:\d+"
    Set ProxyMatch = ProxyRe.Execute(xHttp.responseText)
    If ProxyMatch.count >= 1 Then
        xHttp.setProxy 2, Replace(ProxyMatch.Item(0), "PROXY", "", 1), ""
    End If
End If

xHttp.Open "GET", "https://raw.githubusercontent.com/xfox64x/VBShell/master/README.md", False
xHttp.send
WScript.Echo xHttp.responseText
