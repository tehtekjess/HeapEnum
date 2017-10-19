#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Psapi.h>

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#ifdef HEAP_DLL
#define HEAP_DLL __declspec (dllexport)
#else
#define HEAP_DLL __declspec (dllimport)
#endif

// RtlQueryProcessDebugInformation.DebugInfoClassMask constants
#define PDI_MODULES                       0x01
#define PDI_BACKTRACE                     0x02
#define PDI_HEAPS                         0x04
#define PDI_HEAP_TAGS                     0x08
#define PDI_HEAP_BLOCKS                   0x10
#define PDI_LOCKS                         0x20

#define LF32_FIXED    0x00000001
#define LF32_FREE     0x00000002
#define LF32_MOVEABLE 0x00000004

#pragma pack(push, 1)
typedef struct _DEBUG_BUFFER
{
	HANDLE SectionHandle;
	PVOID SectionBase;
	PVOID RemoteSectionBase;
	ULONG SectionBaseDelta;
	HANDLE EventPairHandle;
	ULONG Unknown[2];
	HANDLE RemoteThreadHandle;
	ULONG InfoClassMask;
	ULONG SizeOfInfo;
	ULONG AllocatedSize;
	ULONG SectionSize;
	PVOID ModuleInformation;
	PVOID BackTraceInformation;
	PVOID HeapInformation;
	PVOID LockInformation;
	PVOID Reserved[8];
} DEBUG_BUFFER, *PDEBUG_BUFFER;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _DEBUG_BUFFER64
{
	//UINT16 _ALIGHMENT;
	UINT64 SectionHandle;
	UINT64 SectionBase;
	UINT64 RemoteSectionBase;
	UINT64 SectionBaseDelta;
	UINT64 EventPairHandle;
	UINT64 Unknown[2];
	UINT64 RemoteThreadHandle;
	UINT64 InfoClassMask;
	UINT64 SizeOfInfo;
	UINT64 AllocatedSize;
	UINT64 SectionSize;
	UINT64 ModuleInformation;
	UINT64 BackTraceInformation;
	UINT64 HeapInformation;
	UINT64 LockInformation;
	UINT64 Reserved[8];
} DEBUG_BUFFER64, *PDEBUG_BUFFER64;
#pragma pack(pop)

//This represents each heap node
#pragma pack(push, 1)
typedef struct _DEBUG_HEAP_INFORMATION
{
	ULONG Base; // 0x00
	ULONG Flags; // 0x04
	USHORT Granularity; // 0x08
	USHORT Unknown; // 0x0A
	ULONG Allocated; // 0x0C
	ULONG Committed; // 0x10
	ULONG TagCount; // 0x14
	ULONG BlockCount; // 0x18
	ULONG Reserved[7]; // 0x1C
	PVOID Tags; // 0x38
	PVOID Blocks; // 0x3C
} DEBUG_HEAP_INFORMATION, *PDEBUG_HEAP_INFORMATION;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _DEBUG_HEAP_INFORMATION64
{
	UINT64 Base; // 0x00
	UINT32 Flags; // 0x04
	UINT16 Granularity; // 0x08
	UINT16 Unknown; // 0x0A
	UINT64 Allocated; // 0x0C
	UINT64 Committed; // 0x10
	UINT32 TagCount; // 0x14
	UINT64 BlockCount; // 0x18
	UINT32 Reserved[7]; // 0x1C
	UINT64 Tags; // 0x38
	UINT64 Blocks; // 0x3C
} DEBUG_HEAP_INFORMATION64, *PDEBUG_HEAP_INFORMATION64;
#pragma pack(pop)

//Internal structure used to store heap block information.
struct HeapBlock
{
	PVOID dwAddress;
	DWORD dwSize;
	DWORD dwFlags;
	ULONG reserved;
};

struct HeapBlock64
{
	UINT64 dwAddress;
	UINT64 dwSize;
	UINT64 dwFlags;
	UINT64 reserved;
};

// Win API Imports
extern "C" __declspec(dllimport) NTSTATUS __stdcall RtlQueryProcessDebugInformation(IN ULONG  ProcessId, IN ULONG  DebugInfoClassMask, IN OUT PDEBUG_BUFFER64  DebugBuffer);
extern "C" __declspec(dllimport) PDEBUG_BUFFER64 __stdcall RtlCreateQueryDebugBuffer(IN ULONG  Size, IN BOOLEAN  EventPair);
extern "C" __declspec(dllimport) NTSTATUS __stdcall RtlDestroyQueryDebugBuffer(IN PDEBUG_BUFFER64  DebugBuffer);

// Main Functions
BOOL HEAP_DLL WINAPI DllMain(HANDLE, DWORD, LPVOID);
int HEAP_DLL DisplayHeapNodes(byte ** output, ULONG ** len, ULONG ProcessId);
int HEAP_DLL DisplayHeapBlocks(byte ** output, ULONG ** len, ULONG ProcessId, void * nodeAddress);
bool HEAP_DLL GetFirstHeapBlock(PDEBUG_HEAP_INFORMATION64 curHeapNode, HeapBlock64 *hb);
bool HEAP_DLL GetNextHeapBlock(PDEBUG_HEAP_INFORMATION64 curHeapNode, HeapBlock64 *hb);
void HEAP_DLL FreeBlock(ULONG * where);
