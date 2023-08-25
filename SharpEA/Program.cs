using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static SharpEA.Program;

namespace SharpEA
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct _FILE_FULL_EA_INFORMATION
        {
            public int NextEntryOffset; //4 bytes
            public byte Flags; // 1 bytes
            public byte EaNameLength; // 1 bytes
            public short EaValueLength; // 2 bytes
            public IntPtr test1;
            public IntPtr test2;
            public IntPtr test3;
            public IntPtr test4;
            public IntPtr test5;
            public IntPtr test6;
            public IntPtr test7;
            public IntPtr test8;
            public IntPtr test9;
            public IntPtr test10;
            public IntPtr test11;
            public IntPtr test12;
            public IntPtr test13;
            public IntPtr test14;
            public IntPtr test15;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct IO_STATUS_BLOCK
        {
            public NtStatus status;
            public IntPtr information;
        }

        [DllImport("ntdll.dll")]
        public static extern NtStatus ZwQueryEaFile(
            SafeFileHandle handle,
            out IO_STATUS_BLOCK ioStatus,
            out _FILE_FULL_EA_INFORMATION buffer,
            // out IntPtr buffer,
            // out byte[] buffer,
            int length,
            bool retSingleEntry,
            IntPtr eaList,
            uint eaListLength,
            uint eaIndex,
            bool restartScan
        );

        
        [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
        public static extern NtStatus ZwSetEaFile(
            SafeFileHandle FileHandle,
            out IO_STATUS_BLOCK IoStatusBlock,
            _FILE_FULL_EA_INFORMATION Buffer,
            int Length
        );
        

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern SafeFileHandle CreateFileW([MarshalAs(UnmanagedType.LPWStr)] string filename, uint access, int share, IntPtr securityAttributes, int creationDisposition, int flagsAndAttributes, IntPtr templateFile);
        [DllImport("kernel32.dll")] static extern uint GetLastError();
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] static extern bool CloseHandle(IntPtr hObject);

        const uint GENERIC_READ = 0x80000000;
        const uint GENERIC_WRITE = 0x40000000;
        const int OPEN_EXISTING = 3;
        const int FILE_ALL_ACCESS = 0x1F01FF;
        const int FILE_READ_EA = 8;
        const int FILE_WRITE_ATTRIBUTES = 0x100;
        const int FILE_SHARE_READ = 0x00000001;
        const int OPEN_ALWAYS = 4;
        const int FILE_FLAG_SEQUENTIAL_SCAN = 0x80;
        const int FILE_ATTRIBUTE_NORMAL = 0x08000000;
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        public enum NtStatus : uint { Success = 0x00000000, Wait1 = 0x00000001, Wait2 = 0x00000002, Wait3 = 0x00000003, Wait63 = 0x0000003f, Abandoned = 0x00000080, AbandonedWait0 = 0x00000080, AbandonedWait1 = 0x00000081, AbandonedWait2 = 0x00000082, AbandonedWait3 = 0x00000083, AbandonedWait63 = 0x000000bf, UserApc = 0x000000c0, KernelApc = 0x00000100, Alerted = 0x00000101, Timeout = 0x00000102, Pending = 0x00000103, Reparse = 0x00000104, MoreEntries = 0x00000105, NotAllAssigned = 0x00000106, SomeNotMapped = 0x00000107, OpLockBreakInProgress = 0x00000108, VolumeMounted = 0x00000109, RxActCommitted = 0x0000010a, NotifyCleanup = 0x0000010b, NotifyEnumDir = 0x0000010c, NoQuotasForAccount = 0x0000010d, PrimaryTransportConnectFailed = 0x0000010e, PageFaultTransition = 0x00000110, PageFaultDemandZero = 0x00000111, PageFaultCopyOnWrite = 0x00000112, PageFaultGuardPage = 0x00000113, PageFaultPagingFile = 0x00000114, CrashDump = 0x00000116, ReparseObject = 0x00000118, NothingToTerminate = 0x00000122, ProcessNotInJob = 0x00000123, ProcessInJob = 0x00000124, ProcessCloned = 0x00000129, FileLockedWithOnlyReaders = 0x0000012a, FileLockedWithWriters = 0x0000012b, Informational = 0x40000000, ObjectNameExists = 0x40000000, ThreadWasSuspended = 0x40000001, WorkingSetLimitRange = 0x40000002, ImageNotAtBase = 0x40000003, RegistryRecovered = 0x40000009, Warning = 0x80000000, GuardPageViolation = 0x80000001, DatatypeMisalignment = 0x80000002, Breakpoint = 0x80000003, SingleStep = 0x80000004, BufferOverflow = 0x80000005, NoMoreFiles = 0x80000006, HandlesClosed = 0x8000000a, PartialCopy = 0x8000000d, DeviceBusy = 0x80000011, InvalidEaName = 0x80000013, EaListInconsistent = 0x80000014, NoMoreEntries = 0x8000001a, LongJump = 0x80000026, DllMightBeInsecure = 0x8000002b, Error = 0xc0000000, Unsuccessful = 0xc0000001, NotImplemented = 0xc0000002, InvalidInfoClass = 0xc0000003, InfoLengthMismatch = 0xc0000004, AccessViolation = 0xc0000005, InPageError = 0xc0000006, PagefileQuota = 0xc0000007, InvalidHandle = 0xc0000008, BadInitialStack = 0xc0000009, BadInitialPc = 0xc000000a, InvalidCid = 0xc000000b, TimerNotCanceled = 0xc000000c, InvalidParameter = 0xc000000d, NoSuchDevice = 0xc000000e, NoSuchFile = 0xc000000f, InvalidDeviceRequest = 0xc0000010, EndOfFile = 0xc0000011, WrongVolume = 0xc0000012, NoMediaInDevice = 0xc0000013, NoMemory = 0xc0000017, NotMappedView = 0xc0000019, UnableToFreeVm = 0xc000001a, UnableToDeleteSection = 0xc000001b, IllegalInstruction = 0xc000001d, AlreadyCommitted = 0xc0000021, AccessDenied = 0xc0000022, BufferTooSmall = 0xc0000023, ObjectTypeMismatch = 0xc0000024, NonContinuableException = 0xc0000025, BadStack = 0xc0000028, NotLocked = 0xc000002a, NotCommitted = 0xc000002d, InvalidParameterMix = 0xc0000030, ObjectNameInvalid = 0xc0000033, ObjectNameNotFound = 0xc0000034, ObjectNameCollision = 0xc0000035, ObjectPathInvalid = 0xc0000039, ObjectPathNotFound = 0xc000003a, ObjectPathSyntaxBad = 0xc000003b, DataOverrun = 0xc000003c, DataLate = 0xc000003d, DataError = 0xc000003e, CrcError = 0xc000003f, SectionTooBig = 0xc0000040, PortConnectionRefused = 0xc0000041, InvalidPortHandle = 0xc0000042, SharingViolation = 0xc0000043, QuotaExceeded = 0xc0000044, InvalidPageProtection = 0xc0000045, MutantNotOwned = 0xc0000046, SemaphoreLimitExceeded = 0xc0000047, PortAlreadySet = 0xc0000048, SectionNotImage = 0xc0000049, SuspendCountExceeded = 0xc000004a, ThreadIsTerminating = 0xc000004b, BadWorkingSetLimit = 0xc000004c, IncompatibleFileMap = 0xc000004d, SectionProtection = 0xc000004e, EasNotSupported = 0xc000004f, EaTooLarge = 0xc0000050, NonExistentEaEntry = 0xc0000051, NoEasOnFile = 0xc0000052, EaCorruptError = 0xc0000053, FileLockConflict = 0xc0000054, LockNotGranted = 0xc0000055, DeletePending = 0xc0000056, CtlFileNotSupported = 0xc0000057, UnknownRevision = 0xc0000058, RevisionMismatch = 0xc0000059, InvalidOwner = 0xc000005a, InvalidPrimaryGroup = 0xc000005b, NoImpersonationToken = 0xc000005c, CantDisableMandatory = 0xc000005d, NoLogonServers = 0xc000005e, NoSuchLogonSession = 0xc000005f, NoSuchPrivilege = 0xc0000060, PrivilegeNotHeld = 0xc0000061, InvalidAccountName = 0xc0000062, UserExists = 0xc0000063, NoSuchUser = 0xc0000064, GroupExists = 0xc0000065, NoSuchGroup = 0xc0000066, MemberInGroup = 0xc0000067, MemberNotInGroup = 0xc0000068, LastAdmin = 0xc0000069, WrongPassword = 0xc000006a, IllFormedPassword = 0xc000006b, PasswordRestriction = 0xc000006c, LogonFailure = 0xc000006d, AccountRestriction = 0xc000006e, InvalidLogonHours = 0xc000006f, InvalidWorkstation = 0xc0000070, PasswordExpired = 0xc0000071, AccountDisabled = 0xc0000072, NoneMapped = 0xc0000073, TooManyLuidsRequested = 0xc0000074, LuidsExhausted = 0xc0000075, InvalidSubAuthority = 0xc0000076, InvalidAcl = 0xc0000077, InvalidSid = 0xc0000078, InvalidSecurityDescr = 0xc0000079, ProcedureNotFound = 0xc000007a, InvalidImageFormat = 0xc000007b, NoToken = 0xc000007c, BadInheritanceAcl = 0xc000007d, RangeNotLocked = 0xc000007e, DiskFull = 0xc000007f, ServerDisabled = 0xc0000080, ServerNotDisabled = 0xc0000081, TooManyGuidsRequested = 0xc0000082, GuidsExhausted = 0xc0000083, InvalidIdAuthority = 0xc0000084, AgentsExhausted = 0xc0000085, InvalidVolumeLabel = 0xc0000086, SectionNotExtended = 0xc0000087, NotMappedData = 0xc0000088, ResourceDataNotFound = 0xc0000089, ResourceTypeNotFound = 0xc000008a, ResourceNameNotFound = 0xc000008b, ArrayBoundsExceeded = 0xc000008c, FloatDenormalOperand = 0xc000008d, FloatDivideByZero = 0xc000008e, FloatInexactResult = 0xc000008f, FloatInvalidOperation = 0xc0000090, FloatOverflow = 0xc0000091, FloatStackCheck = 0xc0000092, FloatUnderflow = 0xc0000093, IntegerDivideByZero = 0xc0000094, IntegerOverflow = 0xc0000095, PrivilegedInstruction = 0xc0000096, TooManyPagingFiles = 0xc0000097, FileInvalid = 0xc0000098, InstanceNotAvailable = 0xc00000ab, PipeNotAvailable = 0xc00000ac, InvalidPipeState = 0xc00000ad, PipeBusy = 0xc00000ae, IllegalFunction = 0xc00000af, PipeDisconnected = 0xc00000b0, PipeClosing = 0xc00000b1, PipeConnected = 0xc00000b2, PipeListening = 0xc00000b3, InvalidReadMode = 0xc00000b4, IoTimeout = 0xc00000b5, FileForcedClosed = 0xc00000b6, ProfilingNotStarted = 0xc00000b7, ProfilingNotStopped = 0xc00000b8, NotSameDevice = 0xc00000d4, FileRenamed = 0xc00000d5, CantWait = 0xc00000d8, PipeEmpty = 0xc00000d9, CantTerminateSelf = 0xc00000db, InternalError = 0xc00000e5, InvalidParameter1 = 0xc00000ef, InvalidParameter2 = 0xc00000f0, InvalidParameter3 = 0xc00000f1, InvalidParameter4 = 0xc00000f2, InvalidParameter5 = 0xc00000f3, InvalidParameter6 = 0xc00000f4, InvalidParameter7 = 0xc00000f5, InvalidParameter8 = 0xc00000f6, InvalidParameter9 = 0xc00000f7, InvalidParameter10 = 0xc00000f8, InvalidParameter11 = 0xc00000f9, InvalidParameter12 = 0xc00000fa, MappedFileSizeZero = 0xc000011e, TooManyOpenedFiles = 0xc000011f, Cancelled = 0xc0000120, CannotDelete = 0xc0000121, InvalidComputerName = 0xc0000122, FileDeleted = 0xc0000123, SpecialAccount = 0xc0000124, SpecialGroup = 0xc0000125, SpecialUser = 0xc0000126, MembersPrimaryGroup = 0xc0000127, FileClosed = 0xc0000128, TooManyThreads = 0xc0000129, ThreadNotInProcess = 0xc000012a, TokenAlreadyInUse = 0xc000012b, PagefileQuotaExceeded = 0xc000012c, CommitmentLimit = 0xc000012d, InvalidImageLeFormat = 0xc000012e, InvalidImageNotMz = 0xc000012f, InvalidImageProtect = 0xc0000130, InvalidImageWin16 = 0xc0000131, LogonServer = 0xc0000132, DifferenceAtDc = 0xc0000133, SynchronizationRequired = 0xc0000134, DllNotFound = 0xc0000135, IoPrivilegeFailed = 0xc0000137, OrdinalNotFound = 0xc0000138, EntryPointNotFound = 0xc0000139, ControlCExit = 0xc000013a, PortNotSet = 0xc0000353, DebuggerInactive = 0xc0000354, CallbackBypass = 0xc0000503, PortClosed = 0xc0000700, MessageLost = 0xc0000701, InvalidMessage = 0xc0000702, RequestCanceled = 0xc0000703, RecursiveDispatch = 0xc0000704, LpcReceiveBufferExpected = 0xc0000705, LpcInvalidConnectionUsage = 0xc0000706, LpcRequestsNotAllowed = 0xc0000707, ResourceInUse = 0xc0000708, ProcessIsProtected = 0xc0000712, VolumeDirty = 0xc0000806, FileCheckedOut = 0xc0000901, CheckOutRequired = 0xc0000902, BadFileType = 0xc0000903, FileTooLarge = 0xc0000904, FormsAuthRequired = 0xc0000905, VirusInfected = 0xc0000906, VirusDeleted = 0xc0000907, TransactionalConflict = 0xc0190001, InvalidTransaction = 0xc0190002, TransactionNotActive = 0xc0190003, TmInitializationFailed = 0xc0190004, RmNotActive = 0xc0190005, RmMetadataCorrupt = 0xc0190006, TransactionNotJoined = 0xc0190007, DirectoryNotRm = 0xc0190008, CouldNotResizeLog = 0xc0190009, TransactionsUnsupportedRemote = 0xc019000a, LogResizeInvalidSize = 0xc019000b, RemoteFileVersionMismatch = 0xc019000c, CrmProtocolAlreadyExists = 0xc019000f, TransactionPropagationFailed = 0xc0190010, CrmProtocolNotFound = 0xc0190011, TransactionSuperiorExists = 0xc0190012, TransactionRequestNotValid = 0xc0190013, TransactionNotRequested = 0xc0190014, TransactionAlreadyAborted = 0xc0190015, TransactionAlreadyCommitted = 0xc0190016, TransactionInvalidMarshallBuffer = 0xc0190017, CurrentTransactionNotValid = 0xc0190018, LogGrowthFailed = 0xc0190019, ObjectNoLongerExists = 0xc0190021, StreamMiniversionNotFound = 0xc0190022, StreamMiniversionNotValid = 0xc0190023, MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024, CantOpenMiniversionWithModifyIntent = 0xc0190025, CantCreateMoreStreamMiniversions = 0xc0190026, HandleNoLongerValid = 0xc0190028, NoTxfMetadata = 0xc0190029, LogCorruptionDetected = 0xc0190030, CantRecoverWithHandleOpen = 0xc0190031, RmDisconnected = 0xc0190032, EnlistmentNotSuperior = 0xc0190033, RecoveryNotNeeded = 0xc0190034, RmAlreadyStarted = 0xc0190035, FileIdentityNotPersistent = 0xc0190036, CantBreakTransactionalDependency = 0xc0190037, CantCrossRmBoundary = 0xc0190038, TxfDirNotEmpty = 0xc0190039, IndoubtTransactionsExist = 0xc019003a, TmVolatile = 0xc019003b, RollbackTimerExpired = 0xc019003c, TxfAttributeCorrupt = 0xc019003d, EfsNotAllowedInTransaction = 0xc019003e, TransactionalOpenNotAllowed = 0xc019003f, TransactedMappingUnsupportedRemote = 0xc0190040, TxfMetadataAlreadyPresent = 0xc0190041, TransactionScopeCallbacksNotSet = 0xc0190042, TransactionRequiredPromotion = 0xc0190043, CannotExecuteFileInTransaction = 0xc0190044, TransactionsNotFrozen = 0xc0190045, MaximumNtStatus = 0xffffffff }


        private static T MarshalBytesTo<T>(byte[] bytes)
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return theStructure;
        }

        public static string Reverse(string s)
        {
            char[] charArray = s.ToCharArray();
            Array.Reverse(charArray);
            return new string(charArray);
        }


        public static string ConvertHex(IntPtr input_number)
        {
            try
            {
                string hexString = input_number.ToString("x");
                string ascii = string.Empty;

                for (int i = 0; i < hexString.Length; i += 2)
                {
                    String hs = string.Empty;

                    hs = hexString.Substring(i, 2);
                    uint decval = System.Convert.ToUInt32(hs, 16);
                    char character = System.Convert.ToChar(decval);
                    ascii += character;

                }

                return Reverse(ascii);
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }

            return string.Empty;
        }

        static void Main(string[] args)
        {
            // Get file handle
            String ea_filename = args[0];
            SafeFileHandle file_handle = CreateFileW(ea_filename, GENERIC_READ , 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (file_handle.IsInvalid)
            {
                Console.WriteLine("[-] Invalid handle. Error code: " + GetLastError());
                System.Environment.Exit(-1);
            }

            //////////////////////////////////////////////////////////////////////////
            // Query EA
            Console.WriteLine("\n[+] Reading... ");
            Console.WriteLine("[+] Struct size: "+ Marshal.SizeOf(typeof(_FILE_FULL_EA_INFORMATION)));
            IO_STATUS_BLOCK IoStatusBlock;
            // int buff_size = 0x100; // Marshal.SizeOf(typeof(_FILE_FULL_EA_INFORMATION))  + 20;
            int buff_size = 128; // Marshal.SizeOf(typeof(_FILE_FULL_EA_INFORMATION)) + 102;
            // byte[] buffer = new byte[buff_size]; //= Marshal.AllocHGlobal(buff_size);
            //IntPtr address_to_free = buffer;
            _FILE_FULL_EA_INFORMATION ffeai = new _FILE_FULL_EA_INFORMATION();
            
            NtStatus status = ZwQueryEaFile(file_handle, out IoStatusBlock, out ffeai, buff_size, false, IntPtr.Zero, 0, 0, true);
            // NtStatus status = ZwQueryEaFile(file_handle, out IoStatusBlock, out buffer, buff_size, false, IntPtr.Zero, 0, 0, true);

            // 0xC0000052 = No EAs
            if (status == NtStatus.NoEasOnFile) {
                Console.WriteLine("[+] No Extended Attributes in this file");
                System.Environment.Exit(0);
            }

            /*
            public int NextEntryOffset;
            public byte Flags;
            public byte EaNameLength;
            public short EaValueLength;
            public char[] EaName;
            public char[] EaValue;
            */
            Console.WriteLine("[+] NtStatus: " + status);
            Console.WriteLine("[+] buff_size:              " + buff_size);
            //Console.WriteLine("[+] address_to_free:        " + address_to_free + " 0x" + address_to_free.ToString("x") + "");
            // Console.WriteLine("[+] buffer:   " + buffer); // + " 0x" + buffer.ToString("x") + "") ; 
            Console.WriteLine("[+] IoStatusBlock.NtStatus:    " + IoStatusBlock.status);
            Console.WriteLine("[+] IoStatusBlock.information: " + IoStatusBlock.information);

            /*
            */
            Console.WriteLine("[+] ffeai.NextEntryOffset: 0x" + ffeai.NextEntryOffset.ToString("x"));
            Console.WriteLine("[+] ffeai.Flags:           0x" + ffeai.Flags.ToString("x"));
            Console.WriteLine("[+] ffeai.EaNameLength:    0x" + ffeai.EaNameLength.ToString("x"));
            Console.WriteLine("[+] ffeai.EaValueLength:   0x" + ffeai.EaValueLength.ToString("x"));


            Console.WriteLine("[+] ffeai.test1:          " + ffeai.test1 + "\t" + ConvertHex(ffeai.test1));
            Console.WriteLine("[+] ffeai.test2:          " + ffeai.test2 + "\t" + ConvertHex(ffeai.test2));
            Console.WriteLine("[+] ffeai.test3:          " + ffeai.test3 + "\t" + ConvertHex(ffeai.test3));
            Console.WriteLine("[+] ffeai.test4:          " + ffeai.test4 + "\t" + ConvertHex(ffeai.test4));
            Console.WriteLine("[+] ffeai.test5:          " + ffeai.test5 + "\t" + ConvertHex(ffeai.test5));
            Console.WriteLine("[+] ffeai.test6:          " + ffeai.test6 + "\t" + ConvertHex(ffeai.test6));
            Console.WriteLine("[+] ffeai.test7:          " + ffeai.test7 + "\t" + ConvertHex(ffeai.test7));
            Console.WriteLine("[+] ffeai.test8:          " + ffeai.test8 + "\t" + ConvertHex(ffeai.test8));
            Console.WriteLine("[+] ffeai.test9:          " + ffeai.test9 + "\t" + ConvertHex(ffeai.test9));
            Console.WriteLine("[+] ffeai.test10:          " + ffeai.test10 + "\t" + ConvertHex(ffeai.test10));
            Console.WriteLine("[+] ffeai.test11:          " + ffeai.test11 + "\t" + ConvertHex(ffeai.test11));
            Console.WriteLine("[+] ffeai.test12:          " + ffeai.test12 + "\t" + ConvertHex(ffeai.test12));
            Console.WriteLine("[+] ffeai.test13:          " + ffeai.test13 + "\t" + ConvertHex(ffeai.test13));
            Console.WriteLine("[+] ffeai.test14:          " + ffeai.test14 + "\t" + ConvertHex(ffeai.test14));
            Console.WriteLine("[+] ffeai.test15:          " + ffeai.test15 + "\t" + ConvertHex(ffeai.test15));


            // Thread.Sleep(1000);
            System.Environment.Exit(0);


            //////////////////////////////////////////////////////////////////////////

            // NtStatus ntstatus_code = (NtStatus)status;
            //Console.WriteLine("[+] NtStatus: "+ status);

            //IntPtr ipHAndle = file_handle.DangerousGetHandle();
            //Console.WriteLine("[+] File Handle: "+ipHAndle);
            //CloseHandle(ipHAndle);

            /*
            Console.WriteLine("\n[+] Writting... ");
            IO_STATUS_BLOCK IoStatusBlock2;
            _FILE_FULL_EA_INFORMATION dumpEA;
            dumpEA.NextEntryOffset = 0;
            dumpEA.Flags = 0;
            dumpEA.EaNameLength = 4;
            dumpEA.EaValueLength = 4;
            //dumpEA.EaName = EAname;
            dumpEA.test1 = 123;
            dumpEA.test2 = 123;
            //Console.WriteLine(sizeof(dumpEA));
            int size = 8;
            NtStatus status1 = ZwSetEaFile(file_handle, out IoStatusBlock2, dumpEA, size);
            Console.WriteLine("[+] NtStatus: " + status1);

            Thread.Sleep(1000);
            System.Environment.Exit(0);
            */
        }
    }
}
