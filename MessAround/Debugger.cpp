#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>

using namespace std;

// NT status types.
#define STATUS_SUCCESS 0
#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_PROCESS_IS_PROTECTED 0xC0000712
#define STATUS_NOT_SUPPORTED 0xC00000BB
#define STATUS_PROCESS_IS_TERMINATING 0xC000010A

// Defines the qword type.
typedef DWORD64 QWORD;

// The debug object parameters structure.
typedef struct _DEBUG_OBJECT_PARAMS
{
	DWORD dwSize; // 0x0
	DWORD padding_0x4; // 0x4

	QWORD qword_0x8; // 0x8
	QWORD qword_0x10; // 0x10

	DWORD dword_0x18; // 0x18
	DWORD padding_0x14; // 0x14

	QWORD dword_0x20; // 0x20
	QWORD dword_0x28; // 0x28

} DEBUG_OBJECT_PARAMS, *PDEBUG_OBJECT_PARAMS;

// NT functions.
EXTERN_C NTSYSAPI NTSTATUS NTAPI BaseSetLastNTError(_In_ NTSTATUS Status);

// NT debug functions.
EXTERN_C NTSYSAPI NTSTATUS NTAPI DbgUiIssueRemoteBreakin(_In_ HANDLE hProcess);
EXTERN_C NTSYSAPI NTSTATUS NTAPI DbgUiStopDebugging(_In_ HANDLE hProcess);

// NT kernel debug functions.
EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwCreateDebugObject(_Out_ PHANDLE hObject, _In_ DWORD arg2, _In_ PDEBUG_OBJECT_PARAMS Params, _In_ DWORD arg4);
EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwDebugActiveProcess(_In_ HANDLE hProcess, _In_ HANDLE hObject);

// Stores the debug object.
HANDLE DebugObject;

// Debug object TEB location.
#define DEBUG_OBJECT_TEB *(HANDLE*)((LPBYTE)NtCurrentTeb() + 0x16A8)

// The access rights of the debug handle.
#define DEBUG_ACCESS (PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME)

// Creates the debug object in the TEB.
NTSTATUS NTAPI DbgUiConnectToDbg()
{
	// Checks if there is already a debug object.
	if (!DebugObject)
	{
		// Creates the debug object parameters structure.
		DEBUG_OBJECT_PARAMS Params;
		// Zeros out the structure
		memset(&Params, 0, sizeof(DEBUG_OBJECT_PARAMS));
		// Sets the size attribute
		Params.dwSize = sizeof(DEBUG_OBJECT_PARAMS);
		// Creates the debug object and returns the result (the function we care about).
		return ZwCreateDebugObject(&DebugObject, 0x1F000F, &Params, 1);
	}
	// Function success.
	return STATUS_SUCCESS;
}

#define POBJECT_TYPE LPVOID
#define KPROCESSOR_MODE BYTE
#define POBJECT_HANDLE_INFORMATION LPVOID
#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))

#define IS_PROTECTED(I) CHECK_BIT(*((PBYTE)I + 0x43C), 0xB)
#define ACCESS_MODE *(BYTE*)(__readgsqword(0x188) + 0x1F6)
#define CURRENT_EPROCESS *(PEPROCESS*)(__readgsqword(0x188) + 0x70)

// Provides access validation on the object handle, and, if access can be granted, returns the corresponding pointer to the object's body.
EXTERN_C NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByHandle(HANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID *Object, POBJECT_HANDLE_INFORMATION HandleInformation);
// Decrements the given object's reference count and performs retention checks.
EXTERN_C NTSYSAPI NTSTATUS NTAPI ObDereferenceObject(LPVOID Object);

// EPROCESS object definition.
typedef struct _EPROCESS
{
	DWORD64 RundownProtect; // 0x178
	DWORD64 Wow64Process; // 0x320
	DWORD Flags2; // 0x43C
} EPROCESS, *PEPROCESS;

// Starts debugging the specified process.
// hProcess - A handle to the process to debug.
// hObject - A handle to the debug object that will be used.
NTSTATUS NTAPI NtDebugActiveProcess(_In_ HANDLE hProcess, _In_ HANDLE hDebug)
{
	// Stores the function status.
	NTSTATUS Status;
	// Gets the previous processor access mode.
	BYTE AccessMode = *(BYTE*)(__readgsqword(0x188) + 0x1F6);
	// Recieves the eprocess pointer.
	PEPROCESS pProcess;
	// Gets the eprocess address of the process handle (will lock the object so it can be edited).
	Status = ObReferenceObjectByHandle(hProcess, 0x800, PsProcessType, AccessMode, (PVOID*)&pProcess, 0);
	// Validates the status.
	if (NT_SUCCESS(Status))
	{
		// Stores the debug object
		PVOID pDebug;
		// Gets the object address of the debug object handle.
		Status = ObReferenceObjectByHandle(hDebug, 0x2, DbgkDebugObjectType, AccessMode, &pDebug, 0);
		// Validates the status.
		if (NT_SUCCESS(Status))
		{
			// Allows us to safely access the eprocess object.
			if (ExfAcquireRundownProtection(&pProcess->RundownProtect))
			{
				// Does some stuff with the debug object and the eprocess object.
				LPVOID Unk;
				DWORD Result = DbgkpPostFakeProcessCreateMessages(pProcess, pObject, &Unk);
				Status = DbgkpSetProcessDebugObject(pProcess, pObject, Result, Unk);
				// Releases the object reference.
				ExfReleaseRundownProtection(&pProcess->RundownProtect);
			}
			// Dereferences the debug object.
			ObDereferenceObject(pObject);
			// Returns the status.
			Status = STATUS_PROCESS_IS_TERMINATING;
		}
		// Dereferences the process object.
		ObDereferenceObject(pProcess);
	}
	// Returns the status of the previous function.
	return Status;
}

// Starts debugging the specified process.
// hProcess - A handle to the process to debug.
// hObject - A handle to the debug object that will be used.
NTSTATUS NTAPI NtDebugActiveProcess(_In_ HANDLE hProcess, _In_ HANDLE hObject)
{
	// Stores the function status.
	NTSTATUS Status;
	// Gets the previous processor access mode.
	BYTE AccessMode = *(BYTE*)(__readgsqword(0x188) + 0x1F6);
	// Recieves the eprocess pointer.
	PEPROCESS pProcess;
	// Gets the eprocess address of the process handle (will lock the object so it can be edited).
	Status = ObReferenceObjectByHandle(hProcess, 0x800, PsProcessType, AccessMode, (PVOID*)&pProcess, 0);
	// Validates the status.
	if (NT_SUCCESS(Status))
	{
		// Gets the our process eprocess object address.
		PEPROCESS pOurProcess = (PEPROCESS)PsGetCurrentProcess();
		// Checks that we're not trying to debug our own process or the system process.
		if (pProcess != pOurProcess && (DWORD64)pProcess != PsInitialSystemProcess)
		{
			// Checks if the previous access mode is not kernel?
			// Checks if the debugging process is a protected process.
			// Checks if the target process is not a protected process.
			if (AccessMode != 1 || CHECK_BIT(pOurProcess->Flags2, 0xB) || !CHECK_BIT(pProcess->Flags2, 0xB))
			{
				// Checks if our process and the target is both wow 64
				if (pOurProcess->Wow64Process == 0 || pProcess->Wow64Process != 0)
				{
					// Stores the debug object
					PVOID pObject;
					// Gets the object address of the debug object handle.
					Status = ObReferenceObjectByHandle(hObject, 0x2, DbgkDebugObjectType, AccessMode, &pObject, 0);
					// Validates the status.
					if (NT_SUCCESS(Status))
					{
						// CODE TO LOCK THE EPROCESS OBJECT FOR EDITING
						if (pProcess->RundownProtect == (pProcess->RundownProtect & 0xFFFFFFFFFFFFFFFE))
						{
							// Referances the eprocess object, so nothign can mess with it when we're working on it.
							// THIS USES AN ATOMIC INSTRUCTION, IT'S A SPINLOCK AND IT SHOULD BE IMPLEMENTED DIFFERENTLY!
							pProcess->RundownProtect = (pProcess->RundownProtect & 0xFFFFFFFFFFFFFFFE) + 2;
						}
						else
						{
							// Allows us to safely access the eprocess object.
							if (!ExfAcquireRundownProtection(&pProcess->RundownProtect))
							{
								// Dereferences the debug object.
								ObDereferenceObject(pObject);
								// Dereferences the process object.
								ObDereferenceObject(pProcess);
								// Returns the status.
								return STATUS_PROCESS_IS_TERMINATING;
							}
						}

						LPVOID Unk;
						DWORD Result = DbgkpPostFakeProcessCreateMessages(pProcess, pObject, &Unk);
						Status = DbgkpSetProcessDebugObject(pProcess, pObject, Result, Unk);

						// CODE TO LOCK THE EPROCESS OBJECT FOR EDITING
						if (pProcess->RundownProtect == (pProcess->RundownProtect & 0xFFFFFFFFFFFFFFFE))
						{
							// Referances the eprocess object, so nothign can mess with it when we're working on it.
							// THIS USES AN ATOMIC INSTRUCTION, IT'S A SPINLOCK AND IT SHOULD BE IMPLEMENTED DIFFERENTLY!
							pProcess->RundownProtect = (pProcess->RundownProtect & 0xFFFFFFFFFFFFFFFE) - 2;
						}
						else
						{
							// Allows us to safely access the eprocess object.
							ExfReleaseRundownProtection(&pProcess->RundownProtect);
						}
						// Dereferences the debug object.
						ObDereferenceObject(pObject);
						// Dereferences the process object.
						ObDereferenceObject(pProcess);
						// Returns the status of the previous function.
						return Status;
					}
					// Dereferences the process object.
					ObDereferenceObject(pProcess);
					// Returns the status of the previous function.
					return Status;
				}
				// Dereferences the process object.
				ObDereferenceObject(pProcess);
				// Returns the status.
				return STATUS_NOT_SUPPORTED;
			}
			// Dereferences the process object.
			ObDereferenceObject(pProcess);
			// Returns the status.
			return STATUS_PROCESS_IS_PROTECTED;
		}
		// Sets the status.
		return STATUS_ACCESS_DENIED;
	}
	// Returns the status of the previous function.
	return Status;
}

// The NT equivalent of DebugActiveProcess.
// hProcess - A handle to the process to debug.
NTSTATUS NTAPI DbgUiDebugActiveProcess(_In_ HANDLE hProcess)
{
	// Stores the function status.
	NTSTATUS Status;
	// Calls the kernel to debug the active process (the function we care about).
	Status = ZwDebugActiveProcess(hProcess, DebugObject);
	// If the status is not an error.
	// if (NT_SUCCESS(Status))
	// {
	// Creates a thread in the target process that triggers a breakpoint (useless).
	// Status = DbgUiIssueRemoteBreakin(hProcess);
	// If the status is an error.
	// if (!NT_SUCCESS(Status))
	// {
	// Stops debugging the process.
	// DbgUiStopDebugging(hProcess);
	// }
	// }
	// Returns the current status.
	return Status;
}

// Enables a debugger to attach to an active process and debug it.
// dwProcessId - The id of the process to debug.
BOOL WINAPI DebugProcess(_In_ DWORD dwProcessId)
{
	// Stores the function status.
	NTSTATUS Status;
	// Creates the debug object.
	Status = DbgUiConnectToDbg();
	// If the status is not an error.
	if (NT_SUCCESS(Status))
	{
		// Opens a process handle.
		HANDLE hProcess = OpenProcess(DEBUG_ACCESS, FALSE, dwProcessId);
		// Validates the handle.
		if (hProcess == INVALID_HANDLE_VALUE) return FALSE;
		// Calls the NT version of DebugActiveProcess with the process handle.
		Status = DbgUiDebugActiveProcess(hProcess);
		// Closes the handle.
		CloseHandle(hProcess);
		// If the status is not an error.
		if (NT_SUCCESS(Status)) return TRUE;
	}
	// Sets the last NT error as the status of the function.
	// BaseSetLastNTError(Status);
	// Function failed.
	return FALSE;
}

// Returns the process id for the given image name.
// lpImageName - The process image name to search for.
DWORD FindProcess(LPCSTR lpImageName)
{
	// gets a snapshot of the system processes
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	// validates the handle
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		// stores the process information
		PROCESSENTRY32 ProcessInfo;
		// sets the structure size
		ProcessInfo.dwSize = sizeof(PROCESSENTRY32);
		// gets the first process
		if (Process32First(hSnapshot, &ProcessInfo))
		{
			// gets the information of the next process
			do
			{
				// checks the process name
				if (_stricmp(ProcessInfo.szExeFile, lpImageName) == 0)
				{
					// returns the pid
					return ProcessInfo.th32ProcessID;
				}
			} while (Process32Next(hSnapshot, &ProcessInfo));
		}
	}
	// else we return null
	return NULL;
}

// The main entry point of the program.
int main(int argc, char *argv[])
{
	// Finds the target process id.
	DWORD ProcessId = FindProcess("Realm.exe");
	// Checks if the process exists.
	if (ProcessId)
	{
		// Debugs the process.
		if (DebugProcess(ProcessId))
		{
			// Notifies the user.
			cout << "Process is successfully being debugged." << endl;
			// Adds the debug object to the TEB (temporary).
			DEBUG_OBJECT_TEB = DebugObject;
			// Enters the debug loop.
			while (TRUE)
			{
				// Receives the debug event information.
				DEBUG_EVENT Event;
				// Waits for a debug event to occur.
				if (WaitForDebugEvent(&Event, 0))
				{
					// cout << Event.dwDebugEventCode << endl;
					// Continues.
					ContinueDebugEvent(Event.dwProcessId, Event.dwThreadId, DBG_CONTINUE);
				}
			}
		}
		else
		{
			// Notifies the user.
			cout << "Could not debug the process." << endl;
		}
	}
	else
	{
		// Notifies the user.
		cout << "Process not found." << endl;
	}
	// Waits for user.
	cin.get();
}