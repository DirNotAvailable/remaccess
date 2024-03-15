' This is a an executor for OfflineTS.ps1. It will run
' any file ending with .ps1 in scripts directory.
Set oFSO = CreateObject("Scripting.FileSystemObject")
Set oShell = CreateObject("WScript.Shell")

' Get the current directory
strCurrentDirectory = oFSO.GetAbsolutePathName(".")

' Iterate through files in the current directory
For Each oFile In oFSO.GetFolder(strCurrentDirectory).Files
    ' Check if the file has a .ps1 extension
    If LCase(oFSO.GetExtensionName(oFile)) = "ps1" Then
        ' Run the PowerShell script
        strArgs = "PowerShell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & oFile.Path & """"
        oShell.Run strArgs, 0, False
    End If
Next

' Clean up objects
Set oFSO = Nothing
Set oShell = Nothing