using System;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;


namespace SharpEA
{
    internal class Program
    {
        // Max number of bytes to retrieve for all EAs
        const int MAX_EA_VALUE_SIZE = 1024;
        const int OPEN_EXISTING = 3;
        const int FILE_READ_EA = 8;
        const int FILE_WRITE_EA = 16;

        public enum NtStatus : uint { Success = 0x00000000, Wait1 = 0x00000001, Wait2 = 0x00000002, Wait3 = 0x00000003, Wait63 = 0x0000003f, Abandoned = 0x00000080, AbandonedWait0 = 0x00000080, AbandonedWait1 = 0x00000081, AbandonedWait2 = 0x00000082, AbandonedWait3 = 0x00000083, AbandonedWait63 = 0x000000bf, UserApc = 0x000000c0, KernelApc = 0x00000100, Alerted = 0x00000101, Timeout = 0x00000102, Pending = 0x00000103, Reparse = 0x00000104, MoreEntries = 0x00000105, NotAllAssigned = 0x00000106, SomeNotMapped = 0x00000107, OpLockBreakInProgress = 0x00000108, VolumeMounted = 0x00000109, RxActCommitted = 0x0000010a, NotifyCleanup = 0x0000010b, NotifyEnumDir = 0x0000010c, NoQuotasForAccount = 0x0000010d, PrimaryTransportConnectFailed = 0x0000010e, PageFaultTransition = 0x00000110, PageFaultDemandZero = 0x00000111, PageFaultCopyOnWrite = 0x00000112, PageFaultGuardPage = 0x00000113, PageFaultPagingFile = 0x00000114, CrashDump = 0x00000116, ReparseObject = 0x00000118, NothingToTerminate = 0x00000122, ProcessNotInJob = 0x00000123, ProcessInJob = 0x00000124, ProcessCloned = 0x00000129, FileLockedWithOnlyReaders = 0x0000012a, FileLockedWithWriters = 0x0000012b, Informational = 0x40000000, ObjectNameExists = 0x40000000, ThreadWasSuspended = 0x40000001, WorkingSetLimitRange = 0x40000002, ImageNotAtBase = 0x40000003, RegistryRecovered = 0x40000009, Warning = 0x80000000, GuardPageViolation = 0x80000001, DatatypeMisalignment = 0x80000002, Breakpoint = 0x80000003, SingleStep = 0x80000004, BufferOverflow = 0x80000005, NoMoreFiles = 0x80000006, HandlesClosed = 0x8000000a, PartialCopy = 0x8000000d, DeviceBusy = 0x80000011, InvalidEaName = 0x80000013, EaListInconsistent = 0x80000014, NoMoreEntries = 0x8000001a, LongJump = 0x80000026, DllMightBeInsecure = 0x8000002b, Error = 0xc0000000, Unsuccessful = 0xc0000001, NotImplemented = 0xc0000002, InvalidInfoClass = 0xc0000003, InfoLengthMismatch = 0xc0000004, AccessViolation = 0xc0000005, InPageError = 0xc0000006, PagefileQuota = 0xc0000007, InvalidHandle = 0xc0000008, BadInitialStack = 0xc0000009, BadInitialPc = 0xc000000a, InvalidCid = 0xc000000b, TimerNotCanceled = 0xc000000c, InvalidParameter = 0xc000000d, NoSuchDevice = 0xc000000e, NoSuchFile = 0xc000000f, InvalidDeviceRequest = 0xc0000010, EndOfFile = 0xc0000011, WrongVolume = 0xc0000012, NoMediaInDevice = 0xc0000013, NoMemory = 0xc0000017, NotMappedView = 0xc0000019, UnableToFreeVm = 0xc000001a, UnableToDeleteSection = 0xc000001b, IllegalInstruction = 0xc000001d, AlreadyCommitted = 0xc0000021, AccessDenied = 0xc0000022, BufferTooSmall = 0xc0000023, ObjectTypeMismatch = 0xc0000024, NonContinuableException = 0xc0000025, BadStack = 0xc0000028, NotLocked = 0xc000002a, NotCommitted = 0xc000002d, InvalidParameterMix = 0xc0000030, ObjectNameInvalid = 0xc0000033, ObjectNameNotFound = 0xc0000034, ObjectNameCollision = 0xc0000035, ObjectPathInvalid = 0xc0000039, ObjectPathNotFound = 0xc000003a, ObjectPathSyntaxBad = 0xc000003b, DataOverrun = 0xc000003c, DataLate = 0xc000003d, DataError = 0xc000003e, CrcError = 0xc000003f, SectionTooBig = 0xc0000040, PortConnectionRefused = 0xc0000041, InvalidPortHandle = 0xc0000042, SharingViolation = 0xc0000043, QuotaExceeded = 0xc0000044, InvalidPageProtection = 0xc0000045, MutantNotOwned = 0xc0000046, SemaphoreLimitExceeded = 0xc0000047, PortAlreadySet = 0xc0000048, SectionNotImage = 0xc0000049, SuspendCountExceeded = 0xc000004a, ThreadIsTerminating = 0xc000004b, BadWorkingSetLimit = 0xc000004c, IncompatibleFileMap = 0xc000004d, SectionProtection = 0xc000004e, EasNotSupported = 0xc000004f, EaTooLarge = 0xc0000050, NonExistentEaEntry = 0xc0000051, NoEasOnFile = 0xc0000052, EaCorruptError = 0xc0000053, FileLockConflict = 0xc0000054, LockNotGranted = 0xc0000055, DeletePending = 0xc0000056, CtlFileNotSupported = 0xc0000057, UnknownRevision = 0xc0000058, RevisionMismatch = 0xc0000059, InvalidOwner = 0xc000005a, InvalidPrimaryGroup = 0xc000005b, NoImpersonationToken = 0xc000005c, CantDisableMandatory = 0xc000005d, NoLogonServers = 0xc000005e, NoSuchLogonSession = 0xc000005f, NoSuchPrivilege = 0xc0000060, PrivilegeNotHeld = 0xc0000061, InvalidAccountName = 0xc0000062, UserExists = 0xc0000063, NoSuchUser = 0xc0000064, GroupExists = 0xc0000065, NoSuchGroup = 0xc0000066, MemberInGroup = 0xc0000067, MemberNotInGroup = 0xc0000068, LastAdmin = 0xc0000069, WrongPassword = 0xc000006a, IllFormedPassword = 0xc000006b, PasswordRestriction = 0xc000006c, LogonFailure = 0xc000006d, AccountRestriction = 0xc000006e, InvalidLogonHours = 0xc000006f, InvalidWorkstation = 0xc0000070, PasswordExpired = 0xc0000071, AccountDisabled = 0xc0000072, NoneMapped = 0xc0000073, TooManyLuidsRequested = 0xc0000074, LuidsExhausted = 0xc0000075, InvalidSubAuthority = 0xc0000076, InvalidAcl = 0xc0000077, InvalidSid = 0xc0000078, InvalidSecurityDescr = 0xc0000079, ProcedureNotFound = 0xc000007a, InvalidImageFormat = 0xc000007b, NoToken = 0xc000007c, BadInheritanceAcl = 0xc000007d, RangeNotLocked = 0xc000007e, DiskFull = 0xc000007f, ServerDisabled = 0xc0000080, ServerNotDisabled = 0xc0000081, TooManyGuidsRequested = 0xc0000082, GuidsExhausted = 0xc0000083, InvalidIdAuthority = 0xc0000084, AgentsExhausted = 0xc0000085, InvalidVolumeLabel = 0xc0000086, SectionNotExtended = 0xc0000087, NotMappedData = 0xc0000088, ResourceDataNotFound = 0xc0000089, ResourceTypeNotFound = 0xc000008a, ResourceNameNotFound = 0xc000008b, ArrayBoundsExceeded = 0xc000008c, FloatDenormalOperand = 0xc000008d, FloatDivideByZero = 0xc000008e, FloatInexactResult = 0xc000008f, FloatInvalidOperation = 0xc0000090, FloatOverflow = 0xc0000091, FloatStackCheck = 0xc0000092, FloatUnderflow = 0xc0000093, IntegerDivideByZero = 0xc0000094, IntegerOverflow = 0xc0000095, PrivilegedInstruction = 0xc0000096, TooManyPagingFiles = 0xc0000097, FileInvalid = 0xc0000098, InstanceNotAvailable = 0xc00000ab, PipeNotAvailable = 0xc00000ac, InvalidPipeState = 0xc00000ad, PipeBusy = 0xc00000ae, IllegalFunction = 0xc00000af, PipeDisconnected = 0xc00000b0, PipeClosing = 0xc00000b1, PipeConnected = 0xc00000b2, PipeListening = 0xc00000b3, InvalidReadMode = 0xc00000b4, IoTimeout = 0xc00000b5, FileForcedClosed = 0xc00000b6, ProfilingNotStarted = 0xc00000b7, ProfilingNotStopped = 0xc00000b8, NotSameDevice = 0xc00000d4, FileRenamed = 0xc00000d5, CantWait = 0xc00000d8, PipeEmpty = 0xc00000d9, CantTerminateSelf = 0xc00000db, InternalError = 0xc00000e5, InvalidParameter1 = 0xc00000ef, InvalidParameter2 = 0xc00000f0, InvalidParameter3 = 0xc00000f1, InvalidParameter4 = 0xc00000f2, InvalidParameter5 = 0xc00000f3, InvalidParameter6 = 0xc00000f4, InvalidParameter7 = 0xc00000f5, InvalidParameter8 = 0xc00000f6, InvalidParameter9 = 0xc00000f7, InvalidParameter10 = 0xc00000f8, InvalidParameter11 = 0xc00000f9, InvalidParameter12 = 0xc00000fa, MappedFileSizeZero = 0xc000011e, TooManyOpenedFiles = 0xc000011f, Cancelled = 0xc0000120, CannotDelete = 0xc0000121, InvalidComputerName = 0xc0000122, FileDeleted = 0xc0000123, SpecialAccount = 0xc0000124, SpecialGroup = 0xc0000125, SpecialUser = 0xc0000126, MembersPrimaryGroup = 0xc0000127, FileClosed = 0xc0000128, TooManyThreads = 0xc0000129, ThreadNotInProcess = 0xc000012a, TokenAlreadyInUse = 0xc000012b, PagefileQuotaExceeded = 0xc000012c, CommitmentLimit = 0xc000012d, InvalidImageLeFormat = 0xc000012e, InvalidImageNotMz = 0xc000012f, InvalidImageProtect = 0xc0000130, InvalidImageWin16 = 0xc0000131, LogonServer = 0xc0000132, DifferenceAtDc = 0xc0000133, SynchronizationRequired = 0xc0000134, DllNotFound = 0xc0000135, IoPrivilegeFailed = 0xc0000137, OrdinalNotFound = 0xc0000138, EntryPointNotFound = 0xc0000139, ControlCExit = 0xc000013a, PortNotSet = 0xc0000353, DebuggerInactive = 0xc0000354, CallbackBypass = 0xc0000503, PortClosed = 0xc0000700, MessageLost = 0xc0000701, InvalidMessage = 0xc0000702, RequestCanceled = 0xc0000703, RecursiveDispatch = 0xc0000704, LpcReceiveBufferExpected = 0xc0000705, LpcInvalidConnectionUsage = 0xc0000706, LpcRequestsNotAllowed = 0xc0000707, ResourceInUse = 0xc0000708, ProcessIsProtected = 0xc0000712, VolumeDirty = 0xc0000806, FileCheckedOut = 0xc0000901, CheckOutRequired = 0xc0000902, BadFileType = 0xc0000903, FileTooLarge = 0xc0000904, FormsAuthRequired = 0xc0000905, VirusInfected = 0xc0000906, VirusDeleted = 0xc0000907, TransactionalConflict = 0xc0190001, InvalidTransaction = 0xc0190002, TransactionNotActive = 0xc0190003, TmInitializationFailed = 0xc0190004, RmNotActive = 0xc0190005, RmMetadataCorrupt = 0xc0190006, TransactionNotJoined = 0xc0190007, DirectoryNotRm = 0xc0190008, CouldNotResizeLog = 0xc0190009, TransactionsUnsupportedRemote = 0xc019000a, LogResizeInvalidSize = 0xc019000b, RemoteFileVersionMismatch = 0xc019000c, CrmProtocolAlreadyExists = 0xc019000f, TransactionPropagationFailed = 0xc0190010, CrmProtocolNotFound = 0xc0190011, TransactionSuperiorExists = 0xc0190012, TransactionRequestNotValid = 0xc0190013, TransactionNotRequested = 0xc0190014, TransactionAlreadyAborted = 0xc0190015, TransactionAlreadyCommitted = 0xc0190016, TransactionInvalidMarshallBuffer = 0xc0190017, CurrentTransactionNotValid = 0xc0190018, LogGrowthFailed = 0xc0190019, ObjectNoLongerExists = 0xc0190021, StreamMiniversionNotFound = 0xc0190022, StreamMiniversionNotValid = 0xc0190023, MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024, CantOpenMiniversionWithModifyIntent = 0xc0190025, CantCreateMoreStreamMiniversions = 0xc0190026, HandleNoLongerValid = 0xc0190028, NoTxfMetadata = 0xc0190029, LogCorruptionDetected = 0xc0190030, CantRecoverWithHandleOpen = 0xc0190031, RmDisconnected = 0xc0190032, EnlistmentNotSuperior = 0xc0190033, RecoveryNotNeeded = 0xc0190034, RmAlreadyStarted = 0xc0190035, FileIdentityNotPersistent = 0xc0190036, CantBreakTransactionalDependency = 0xc0190037, CantCrossRmBoundary = 0xc0190038, TxfDirNotEmpty = 0xc0190039, IndoubtTransactionsExist = 0xc019003a, TmVolatile = 0xc019003b, RollbackTimerExpired = 0xc019003c, TxfAttributeCorrupt = 0xc019003d, EfsNotAllowedInTransaction = 0xc019003e, TransactionalOpenNotAllowed = 0xc019003f, TransactedMappingUnsupportedRemote = 0xc0190040, TxfMetadataAlreadyPresent = 0xc0190041, TransactionScopeCallbacksNotSet = 0xc0190042, TransactionRequiredPromotion = 0xc0190043, CannotExecuteFileInTransaction = 0xc0190044, TransactionsNotFrozen = 0xc0190045, MaximumNtStatus = 0xffffffff }
        [StructLayout(LayoutKind.Sequential, Pack = 0)] public struct IO_STATUS_BLOCK { public NtStatus status; public IntPtr information; }
        [StructLayout(LayoutKind.Sequential, Pack = 0)] public unsafe struct _FILE_FULL_EA_INFORMATION { public int NextEntryOffset; public byte Flags; public byte EaNameLength; public short EaValueLength; public fixed byte EaContent[MAX_EA_VALUE_SIZE]; }
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)] public static extern NtStatus ZwSetEaFile(SafeFileHandle FileHandle, out IO_STATUS_BLOCK IoStatusBlock, IntPtr Buffer, int Length);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern SafeFileHandle CreateFileW([MarshalAs(UnmanagedType.LPWStr)] string filename, uint access, int share, IntPtr securityAttributes, int creationDisposition, int flagsAndAttributes, IntPtr templateFile);
        [DllImport("kernel32.dll")] static extern uint GetLastError();
        [DllImport("ntdll.dll")] public static extern NtStatus ZwQueryEaFile(SafeFileHandle handle, out IO_STATUS_BLOCK ioStatus, out _FILE_FULL_EA_INFORMATION buffer, int length, bool retSingleEntry, IntPtr eaList, uint eaListLength, uint eaIndex, bool restartScan);


        static String readEA(byte[] data, int offset, int ea_name_length, int ea_value_length, bool debug = false)
        {
            // Ea Name
            byte[] name_bytes = data.Skip(offset).Take(ea_name_length).ToArray();
            var name_str = System.Text.Encoding.Default.GetString(name_bytes);
            if (debug)
            {
                Console.WriteLine("[+] EA Name:                     {0}", name_str);
                Console.WriteLine("[+] EA Content: ");
            }
            // EA Value
            for (int i = (offset + ea_name_length + 1); i < (offset + ea_name_length + 1 + ea_value_length); i = i + 8)
            {
                String value_str = "";
                for (int j = 0; j < 8; j++)
                {
                    byte byte_to_test = data[i + j];
                    String caracter = System.Text.Encoding.ASCII.GetString(new[] { byte_to_test });                    
                    char c = (char)data[i+j];
                    if (!Char.IsControl(c) || Char.IsWhiteSpace(c)) {
                        value_str += caracter;
                    }
                    else
                    {
                        value_str += ".";
                    }
                }
                if (debug) {
                    Console.WriteLine("{0}   {1}   {2}   {3}   {4}   {5}   {6}   {7}\t\t{8}", data[i].ToString("X2"), data[i + 1].ToString("X2"), data[i + 2].ToString("X2"), data[i + 3].ToString("X2"), data[i + 4].ToString("X2"), data[i + 5].ToString("X2"), data[i + 6].ToString("X2"), data[i + 7].ToString("X2"), value_str);
                }
            }
            return name_str;
        }


        static int readvals(byte[] data, int offset)
        {
            // NextEntryOffset
            byte[] next_entry = data.Skip(offset - 8).Take(4).ToArray();
            int next_entry_int = BitConverter.ToInt32(next_entry, 0);
            // Flags
            byte flags = data[offset - 4];
            // EaNameLength
            byte ea_name_length_byte = data[offset - 3];
            int ea_name_length = (int)ea_name_length_byte;
            // EaValueLength
            short ea_value_length_short = (short)(data[offset - 2] | (data[offset - 1] << 8));
            int ea_value_length = (int)ea_value_length_short;

            Console.WriteLine("");
            Console.WriteLine("[+] NextEntryOffset:             {0} (0x{1})", next_entry_int, next_entry_int.ToString("x"));
            Console.WriteLine("[+] Flags:                       {0} (0x{1})", flags, flags.ToString("x"));
            Console.WriteLine("[+] EaNameLength:                {0} (0x{1})", ea_name_length, ea_name_length.ToString("x"));
            Console.WriteLine("[+] EaValueLength:               {0} (0x{1})", ea_value_length, ea_value_length.ToString("x"));

            readEA(data, offset, ea_name_length, ea_value_length, true);

            return next_entry_int;
        }


        static void read(String ea_filename)
        {
            SafeFileHandle file_handle = CreateFileW(ea_filename, FILE_READ_EA, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (file_handle.IsInvalid)
            {
                Console.WriteLine("[-] Invalid handle. Error code: " + GetLastError());
                System.Environment.Exit(-1);
            }

            // Query EA
            IO_STATUS_BLOCK IoStatusBlock;
            int buff_size = 8 + MAX_EA_VALUE_SIZE;
            _FILE_FULL_EA_INFORMATION ffeai = new _FILE_FULL_EA_INFORMATION();
            NtStatus status = ZwQueryEaFile(file_handle, out IoStatusBlock, out ffeai, buff_size, false, IntPtr.Zero, 0, 0, true);

            if (status == NtStatus.NoEasOnFile)
            {
                Console.WriteLine("[+] No Extended Attributes (EAs) in this file");
                System.Environment.Exit(0);
            }

            int ea_name_length = ffeai.EaNameLength;
            int ea_value_length = ffeai.EaValueLength;
            int next_entry = ffeai.NextEntryOffset;

            byte[] ea_content_arr;
            unsafe
            {
                ea_content_arr = new byte[MAX_EA_VALUE_SIZE];
                Marshal.Copy((IntPtr)ffeai.EaContent, ea_content_arr, 0, MAX_EA_VALUE_SIZE);
            }

            /*
            // DEBUG
            for (int i = 0; i < MAX_EA_VALUE_SIZE; i = i + 8)
            {
                String value_str = "";
                for (int j = 0; j < 8; j++)
                {
                    byte byte_to_test = ea_content_arr[i + j];
                    String caracter = System.Text.Encoding.ASCII.GetString(new[] { byte_to_test });
                    if (regex.IsMatch(caracter))
                    {
                        value_str += caracter;
                    }
                    else
                    {
                        value_str += ".";
                    }
                }
                Console.WriteLine("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}\t{7}\t\t{8}", ea_content_arr[i], ea_content_arr[i + 1], ea_content_arr[i + 2], ea_content_arr[i + 3], ea_content_arr[i + 4], ea_content_arr[i + 5], ea_content_arr[i + 6], ea_content_arr[i + 7], value_str);
            }
            */

            Console.WriteLine("[+] NtStatus:                    {0}", status);
            Console.WriteLine("[+] IoStatusBlock.NtStatus:      {0}", IoStatusBlock.status);
            Console.WriteLine("[+] IoStatusBlock.information:   {0} (0x{1})\n", IoStatusBlock.information, IoStatusBlock.information.ToString("X"));
            Console.WriteLine("[+] NextEntryOffset:             {0} (0x{1})", next_entry, ffeai.NextEntryOffset.ToString("x"));
            Console.WriteLine("[+] Flags:                       {0} (0x{1})", ffeai.Flags, ffeai.Flags.ToString("x"));
            Console.WriteLine("[+] EaNameLength:                {0} (0x{1})", ea_name_length, ea_name_length.ToString("x"));
            Console.WriteLine("[+] EaValueLength:               {0} (0x{1})", ea_value_length, ea_value_length.ToString("x"));

            readEA(ea_content_arr, 0, ea_name_length, ea_value_length, true);

            if (next_entry == 0)
            {
                return;
            }
            else 
            {
                int aux = -1;
                while (aux != 0)
                {
                    aux = readvals(ea_content_arr, next_entry);
                    next_entry += aux;
                }
            }
        }


        public static byte[] ToByteArray(String hexString)
        {
            byte[] retval = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
                retval[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return retval;
        }


        static byte[] getPayload(String payload_str)
        {
            byte[] buf = { };

            // Hexadecimal payload
            if (payload_str.Length >= 2)
            {
                if (payload_str.Substring(0, 2) == "0x")
                {
                    try
                    {
                        payload_str = payload_str.Replace("0x", "");
                        buf = ToByteArray(payload_str);
                        return buf;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[-] Failure trying to decode hexadecimal payload.");
                        Console.WriteLine(ex.ToString());
                        System.Environment.Exit(-1);
                    }
                }
            }

            // Payload from url, http or https
            if (payload_str.Length >= 4)
            {
                if (payload_str.Substring(0, 4) == "http")
                {
                    Console.WriteLine("[+] Getting payload from url: " + payload_str);
                    System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                    System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
                    using (System.Net.WebClient myWebClient = new System.Net.WebClient())
                    {
                        try
                        {
                            System.Net.ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
                            buf = myWebClient.DownloadData(payload_str);
                            return buf;
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("[-] Failure trying to download the file from url: {0}.", payload_str);
                            Console.WriteLine(ex.ToString());
                            System.Environment.Exit(-1);
                        }
                    }
                }
            }

            // Regular payload 
            buf = System.Text.Encoding.ASCII.GetBytes(payload_str);
            return buf;
        }


        static void writeEA(String ea_filename, String ea_name_str, String ea_value_str, bool debug = false)
        {
            IO_STATUS_BLOCK IoStatusBlock;
            _FILE_FULL_EA_INFORMATION ffeai;

            ffeai.NextEntryOffset = 0;
            ffeai.Flags = 0;

            // Name
            byte[] ea_name_bytearr = System.Text.Encoding.Default.GetBytes(ea_name_str);
            ffeai.EaNameLength = (byte)ea_name_str.Length;

            // Value
            byte[] ea_value_bytearr = getPayload(ea_value_str); // System.Text.Encoding.Default.GetBytes(ea_value_str);
            ffeai.EaValueLength = (short)ea_value_bytearr.Length;

            // Build byte array eaname + eavalue
            byte[] aux_bytearr = { (byte)0 };
            int ea_content_arr_size = ea_name_str.Length + 1 + ea_value_bytearr.Length;
            byte[] ea_content_arr = new byte[ea_content_arr_size];

            System.Buffer.BlockCopy(ea_name_bytearr, 0, ea_content_arr, 0, ea_name_bytearr.Length);
            System.Buffer.BlockCopy(aux_bytearr, 0, ea_content_arr, ea_name_bytearr.Length, aux_bytearr.Length);
            System.Buffer.BlockCopy(ea_value_bytearr, 0, ea_content_arr, ea_name_bytearr.Length + aux_bytearr.Length, ea_value_bytearr.Length);

            // Open handle to file
            SafeFileHandle file_handle = CreateFileW(ea_filename, FILE_WRITE_EA, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (file_handle.IsInvalid)
            {
                Console.WriteLine("[-] Invalid handle. Error code: " + GetLastError());
                System.Environment.Exit(-1);
            }

            IntPtr ffeai_pointer = IntPtr.Zero;

            unsafe
            {
                // Copy the EA content to the address of ffeai.EaContent
                // Pointer to the ffeai.EaContent (we need unsafe)
                byte* p = ffeai.EaContent;
                IntPtr ptr = (IntPtr)p;                
                foreach (byte b in ea_content_arr)
                {
                    *p = b;
                    p += 1;
                }

                // Pointer to the structure (we need unsafe)
                ffeai_pointer = (IntPtr)(&ffeai);
            }

            // Call ZwSetEaFile
            NtStatus status1 = ZwSetEaFile(file_handle, out IoStatusBlock, ffeai_pointer, (8 + ea_content_arr_size));

            if (debug) {
                Console.WriteLine("[+] Pointer:  " + ffeai_pointer);
                Console.WriteLine("[+] Size:     " + (8 + ea_content_arr_size));
                Console.WriteLine("[+] NtStatus: " + (NtStatus)status1 + " \t0x" + status1.ToString("X"));
                Console.WriteLine("[+] IoStatusBlock.NtStatus:      " + IoStatusBlock.status);
                Console.WriteLine("[+] IoStatusBlock.information:   " + IoStatusBlock.information);
            }
            
        }


        static void clearEAs(String ea_filename) {
            SafeFileHandle file_handle = CreateFileW(ea_filename, FILE_READ_EA, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (file_handle.IsInvalid)
            {
                Console.WriteLine("[-] Invalid handle. Error code: " + GetLastError());
                System.Environment.Exit(-1);
            }

            while (true) {
                // Query EA
                IO_STATUS_BLOCK IoStatusBlock;
                int buff_size = 8 + MAX_EA_VALUE_SIZE;
                _FILE_FULL_EA_INFORMATION ffeai = new _FILE_FULL_EA_INFORMATION();
                NtStatus status = ZwQueryEaFile(file_handle, out IoStatusBlock, out ffeai, buff_size, false, IntPtr.Zero, 0, 0, true);

                if (status == NtStatus.NoEasOnFile)
                {
                    Console.WriteLine("[+] All Extended Attributes (EAs) were cleared.");
                    System.Environment.Exit(0);
                }

                int ea_name_length = ffeai.EaNameLength;
                int ea_value_length = ffeai.EaValueLength;
                int next_entry = ffeai.NextEntryOffset;

                byte[] ea_content_arr;
                unsafe
                {
                    ea_content_arr = new byte[MAX_EA_VALUE_SIZE];
                    Marshal.Copy((IntPtr)ffeai.EaContent, ea_content_arr, 0, MAX_EA_VALUE_SIZE);
                }

                String ea_name = readEA(ea_content_arr, 0, ea_name_length, ea_value_length);
                Console.WriteLine("[+] Deleting EA with name \"{0}\"",ea_name);
                writeEA(ea_filename, ea_name, "");
            }

        }


        static void getHelp()
        {
            Console.WriteLine("[+] SharpEA.exe [option] (args) ");
            Console.WriteLine("");

            Console.WriteLine("[+] SharpEA.exe list FILE_PATH");
            Console.WriteLine("[+] Example: SharpEA.exe list c:\\windows\\system32\\kernel32.dll");
            Console.WriteLine("");

            Console.WriteLine("[+] SharpEA.exe write FILE_PATH EA_NAME PAYLOAD");
            Console.WriteLine("[+] Example (string):      SharpEA.exe write c:\\Temp\\test.txt EA_name1 RandomString");
            Console.WriteLine("[+] Example (hexadecimal): SharpEA.exe write c:\\Temp\\test.txt EA_name2 0x4142434445");
            Console.WriteLine("[+] Example (from url):    SharpEA.exe write c:\\Temp\\test.txt EA_name3 http://127.0.0.1:8000/payload.bin");
            Console.WriteLine("");

            Console.WriteLine("[+] SharpEA.exe delete FILE_PATH EA_NAME");
            Console.WriteLine("[+] Example: SharpEA.exe delete c:\\Temp\\test.txt EA_name1");
            Console.WriteLine("");

            Console.WriteLine("[+] SharpEA.exe clear FILE_PATH");
            Console.WriteLine("[+] Example: SharpEA.exe clear c:\\Temp\\test.txt");

            System.Environment.Exit(0);
        }


        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                getHelp();
            }
            String option = args[0];
            String ea_filename = args[1];

            if (option == "list")
            {
                Console.WriteLine("[+] Listing EAs...");
                read(ea_filename);
                return;
            }

            else if (option == "write")
            {
                if (args.Length < 4)
                {
                    getHelp();
                }
                String ea_name_str = args[2];
                String ea_value_str = args[3];
                Console.WriteLine("[+] Writting content to EA with name \"{0}\"...", ea_name_str);
                writeEA(ea_filename, ea_name_str, ea_value_str, true);
                return;
            }

            else if (option == "delete")
            {
                if (args.Length < 3)
                {
                    getHelp();
                }
                String ea_name_str = args[2];
                Console.WriteLine("[+] Deleting EA with name \"{0}\"...", ea_name_str);
                writeEA(ea_filename, ea_name_str, "");
                return;
            }

            else if (option == "clear")
            {
                Console.WriteLine("[+] Clearing EAs...");
                clearEAs(ea_filename);
                return;
            }

            else
            {
                getHelp();
            }
        }
    }
}
