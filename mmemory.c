///////////////////////////////////////////////////////////////////////////////
// Used abbreviations
///////////////////////////////////////////////////////////////////////////////
// VAS = Virtual Address Space
// va = virtual address
// pa = physical address
///////////////////////////////////////////////////////////////////////////////


#include <stdlib.h>
#include "mmemory.h"

#define VAS_SIZE (1000 * 1024) // MB


// struct definitions

typedef struct
{
	VA vaStartAddress;
	long nSize;

} Segment;

typedef struct
{
	Segment segment;
	void* pAddress;

} SegmentRecord;

typedef struct
{
	SegmentRecord* pFirstRecord;
	int nSize;

} SegmentTable;

//

#define RESERVED_SEG_TABLE_SIZE (sizeof(SegmentRecord) * 1000)

// globals

void* g_paStartAddress;
SegmentTable* g_pSegmentTable;

//


int m_malloc(VA* ptr, size_t szBlock)
{
	return 1;
}

int m_free(VA ptr)
{
	return 1;
}

int m_read(VA ptr, void* pBuffer, size_t szBuffer)
{
	return 1;
}

int m_write(VA ptr, void* pBuffer, size_t szBuffer)
{
	return 1;
}

int m_init(int n, int szPage)
{
	long nTotalMemory = n * szPage;
	if (nTotalMemory <= 0)
		return -1;

	g_paStartAddress = malloc(nTotalMemory);
	if (!g_paStartAddress)
		return 1;

	g_pSegmentTable = (SegmentTable*)g_paStartAddress;
	g_paStartAddress = g_paStartAddress + RESERVED_SEG_TABLE_SIZE;

	g_pSegmentTable->pFirstRecord = NULL;
	g_pSegmentTable->nSize = 0;

	return 0;
}