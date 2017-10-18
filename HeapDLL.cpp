#include "HeapDLL.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Psapi.h>
#include <inttypes.h>

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"psapi.lib")

BOOL APIENTRY DllMain(HANDLE, DWORD, LPVOID)
{
	return TRUE;
}


int DisplayHeapNodes(byte ** output, ULONG ** len, ULONG pid) {
	// Create debug buffer
	PDEBUG_BUFFER64 db = RtlCreateQueryDebugBuffer(0, FALSE);

	// Get process heap data
	NTSTATUS tmp = RtlQueryProcessDebugInformation(pid, PDI_HEAPS | PDI_HEAP_BLOCKS, db);

	// Return if unable to read process debug information
	if (tmp != 0x0)
		return tmp;

	ULONG heapNodeCount = db->HeapInformation ? *PULONG(db->HeapInformation) : 0;

	// Set and calculate the length buffer
	*len = (ULONG *)malloc(sizeof(ULONG));
	ULONG watasd = heapNodeCount * sizeof(DEBUG_HEAP_INFORMATION64);
	memcpy(*len, &watasd, sizeof(ULONG));

	//Fetch the heap info array
	PDEBUG_HEAP_INFORMATION64 heapInfo = (PDEBUG_HEAP_INFORMATION64)(PULONG(db->HeapInformation) + 2);

	// Set and zero out the return buffer
	*output = (byte *)malloc(watasd + 1);
	memcpy(*output, heapInfo, watasd);

	/* Clean up the buffer*/
	RtlDestroyQueryDebugBuffer(db);
	return 0x0;
}

int DisplayHeapBlocks(byte ** output, ULONG ** len, ULONG pid, void * nodeAddress) {
	HeapBlock64 hb = { 0,0,0,0 };

	// Create debug buffer
	PDEBUG_BUFFER64 db = RtlCreateQueryDebugBuffer(0, FALSE);

	// Get process heap data
	NTSTATUS ret = RtlQueryProcessDebugInformation(pid, PDI_HEAPS | PDI_HEAP_BLOCKS, db);

	// Return if unable to read process debug information
	if (ret != 0x0)
		return ret;

	ULONG heapNodeCount = db->HeapInformation ? *PULONG(db->HeapInformation) : 0;

	//PDEBUG_HEAP_INFORMATION heapInfo = PDEBUG_HEAP_INFORMATION(PULONG(db->HeapInformation) + 1);  // 32 bit
	PDEBUG_HEAP_INFORMATION64 heapInfo = (PDEBUG_HEAP_INFORMATION64)(PULONG(db->HeapInformation) + 2);  // 64 bit

	// Go through each of the heap nodes 
	for (unsigned int i = 0; i < heapNodeCount; i++)
	{
		if (heapInfo[i].Base == (UINT64)nodeAddress) {


			*len = (ULONG *)malloc(sizeof(ULONG));
			ULONG watasd = heapInfo[i].BlockCount * sizeof(HeapBlock64);
			memcpy(*len, &watasd, sizeof(ULONG));

			// Set and zero out the return buffer
			*output = (byte *)malloc(watasd + 1);
			memset(*output, 0, watasd);

			// Now enumerate all blocks within this heap node...
			int c = 0;
			memset(&hb, 0, sizeof(hb));

			if (GetFirstHeapBlock(&heapInfo[i], &hb))
			{
				do
				{
					//Fetch the address offset into the buffer
					byte * ok = (byte*)*output + (c * sizeof(HeapBlock64));

					// Copy the heapblock into the buffer at the address of the offset
					memcpy((byte*)ok, &hb, sizeof(HeapBlock64));

					c++;
				} while (GetNextHeapBlock(&heapInfo[i], &hb));
			}

			// We have our node now so lets exist out of the loop
			break;
		}

	}

	// Clean up the buffer
	RtlDestroyQueryDebugBuffer(db);

	return 0x0;
}

//Get the frist heap block in a node list
bool GetFirstHeapBlock(PDEBUG_HEAP_INFORMATION64 curHeapNode, HeapBlock64 *hb) {
	int *block;

	hb->reserved = 0;
	hb->dwAddress = 0;
	hb->dwFlags = 0;

	block = (int*)curHeapNode->Blocks;

	while ((*(block + 2) & 2) == 2)
	{
		hb->reserved++;
		//hb->dwAddress = (UINT64)(*(block + 6) + curHeapNode->Granularity);
		UINT64 blockAddressLower = ((*(block + 6) >> 32) << 32) + curHeapNode->Granularity;
		UINT64 blockAddressUpper = (*(block + 7) << 32);
		hb->dwAddress = blockAddressLower + (blockAddressUpper << 32);
		block = block + 8;
		hb->dwSize = *block;
	}

	// Update the flags...
	USHORT flags = *(block + 2);

	if ((flags & 0xF1) != 0 || (flags & 0x0200) != 0)
		hb->dwFlags = 1;
	else if ((flags & 0x20) != 0)
		hb->dwFlags = 4;
	else if ((flags & 0x0100) != 0)
		hb->dwFlags = 2;

	return TRUE;
}

//Get the rest of the heap blocks in a node list
bool GetNextHeapBlock(PDEBUG_HEAP_INFORMATION64 curHeapNode, HeapBlock64 *hb) {
	int *block;

	hb->reserved++;
	block = (int*)curHeapNode->Blocks;

	// Make it point to next block address entry
	block = block + hb->reserved * 8;

	// If all the blocks have been enumerated....exit
	if (hb->reserved >= curHeapNode->BlockCount)
		return FALSE;

	if ((*(block + 2) & 2) == 2)
	{
		do
		{
			// new address = curBlockAddress + Granularity ;
			//hb->dwAddress = (UINT64)(*(block + 6) + curHeapNode->Granularity);
			UINT64 blockAddressLower = ((*(block + 6) >> 32) << 32) + curHeapNode->Granularity;
			UINT64 blockAddressUpper = (*(block + 7) << 32);
			hb->dwAddress = blockAddressLower + (blockAddressUpper << 32);

			hb->reserved++;
			block = block + 8; //move to next block
			hb->dwSize = *block;

		} while ((*(block + 2) & 2) == 2);
	}
	else
	{
		// New Address = prev Address + prev block size ;
		hb->dwAddress = (UINT64)((UINT64)hb->dwAddress + hb->dwSize);
		hb->dwSize = *block;
	}

	// Update the flags...
	USHORT flags = *(block + 2);

	if ((flags & 0xF1) != 0 || (flags & 0x0200) != 0)
		hb->dwFlags = 1;
	else if ((flags & 0x20) != 0)
		hb->dwFlags = 4;
	else if ((flags & 0x0100) != 0)
		hb->dwFlags = 2;

	return TRUE;
}

