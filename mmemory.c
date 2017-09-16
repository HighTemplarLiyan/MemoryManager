///////////////////////////////////////////////////////////////////////////////
// Used abbreviations
///////////////////////////////////////////////////////////////////////////////
// VAS = Virtual Address Space
// va = virtual address
// pa = physical address
///////////////////////////////////////////////////////////////////////////////


#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "mmemory.h"

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
	bool bPresent;

} SegmentRecord;

typedef struct
{
	SegmentRecord* pFirstRecord;
	int nSize;

} SegmentTable;

///////////////////////////////////////////////////////////////////////////////


#define VAS_SIZE (1000 * 1024 * 1024) // MB
#define RESERVED_SEG_TABLE_SIZE (sizeof(SegmentTable) + sizeof(SegmentRecord) * 1000)

// globals

void* g_paStartAddress;

VA g_vaFirstFree = NULL;
const VA g_vaLastAvailable = NULL + VAS_SIZE / sizeof(VA) - 1;

SegmentTable* g_pSegmentTable;

///////////////////////////////////////////////////////////////////////////////

void insert_new_record_into_table(VA vaSegmentAddress, size_t nSegmentSize)
{
	SegmentRecord* pNewRecord = g_pSegmentTable->pFirstRecord + g_pSegmentTable->nSize;

	SegmentRecord tmpRecord;
	tmpRecord.pAddress = NULL;
	tmpRecord.bPresent = false;
	tmpRecord.segment.vaStartAddress = vaSegmentAddress;
	tmpRecord.segment.nSize = nSegmentSize;

	memcpy((void*)pNewRecord, (void*)&tmpRecord, sizeof(SegmentRecord));

	g_pSegmentTable->nSize++;

	g_vaFirstFree = vaSegmentAddress + nSegmentSize - 1;
}

int m_malloc(VA* ptr, size_t szBlock)
{
	if (!szBlock)
		return -1;

	VA vaEndAddress = g_vaFirstFree + szBlock;

	if (vaEndAddress > g_vaLastAvailable)
		return -2;

	insert_new_record_into_table(g_vaFirstFree, szBlock);
	return 0;
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

	SegmentTable tmpTable;
	tmpTable.pFirstRecord = (SegmentRecord*)g_pSegmentTable + sizeof(SegmentTable);
	tmpTable.nSize = 0;
	memcpy((void*)g_pSegmentTable, (void*)&tmpTable, sizeof(SegmentTable));

	g_vaFirstFree = NULL;

	return 0;
}