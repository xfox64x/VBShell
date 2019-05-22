Function WriteFile(FilePath, FileContent)
    Set FsoObj = CreateObject("Scripting.FileSystemObject")
    Set FileObj = FsoObj.CreateTextFile(FilePath,True)
    FileObj.Write FileContent
    FileObj.Close
    WriteFile = True
End Function

Function ExecCmd(CommandLine)    
    Set ExecObj = Shell.Exec(CommandLine)
    TempResults = ""
    Do Until ExecObj.StdOut.AtEndOfStream
        TempResults = Results & ExecObj.StdOut.ReadAll()
    Loop
    ExecCmd = TempResults
End Function

Function SilentExecCmd(CommandLine)    
    Shell.Run CommandLine, 0, True
End Function
