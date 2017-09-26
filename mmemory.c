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

struct Segment
{
	VA vaStartAddress;
	long nSize;
	struct Segment* pNextSegment;

};
typedef struct Segment Segment;

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
#define SEG_TABLE_SIZE(MAX_SEGMENTS) (sizeof(SegmentTable) + sizeof(SegmentRecord) * MAX_SEGMENTS)

// globals

void* g_paStartAddress;

VA g_vaFirstFree = NULL;
const VA g_vaLastAvailable = NULL + VAS_SIZE / sizeof(VA) - 1;

SegmentTable* g_pSegmentTable;
int g_nMaxSegments;
long g_nMemoryReservedForTable;

///////////////////////////////////////////////////////////////////////////////

SegmentRecord* insert_new_record_into_table(VA vaSegmentAddress, size_t nSegmentSize)
{
	size_t nTableSize = g_pSegmentTable->nSize;

	SegmentRecord* pNewRecord = g_pSegmentTable->pFirstRecord + nTableSize;

	SegmentRecord tmpRecord;
	tmpRecord.pAddress = NULL;
	tmpRecord.bPresent = false;
	tmpRecord.segment.vaStartAddress = vaSegmentAddress;
	tmpRecord.segment.nSize = nSegmentSize;
	tmpRecord.segment.pNextSegment = NULL;

	memcpy((void*)pNewRecord, (void*)&tmpRecord, sizeof(SegmentRecord));

	// link previous segment to the new one
	if (nTableSize > 1)
		g_pSegmentTable->pFirstRecord[nTableSize - 1].segment.pNextSegment = &(pNewRecord->segment);

	g_pSegmentTable->nSize++;
	g_vaFirstFree = vaSegmentAddress + nSegmentSize - 1;

	return pNewRecord;
}

int m_malloc(VA* ptr, size_t szBlock)
{
	if (!szBlock)
		return -1;

	VA vaEndAddress = g_vaFirstFree + szBlock;

	if (vaEndAddress > g_vaLastAvailable)
		return -2;

	SegmentRecord* pNewRecord = insert_new_record_into_table(g_vaFirstFree, szBlock);
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
	if (n <= 0 || szPage <= 0)
		return -1;

	g_nMaxSegments = n;
	long nTotalMemory = n * szPage;

	g_paStartAddress = malloc(nTotalMemory);
	if (!g_paStartAddress)
		return 1;

	g_pSegmentTable = (SegmentTable*)g_paStartAddress;
	g_paStartAddress = g_paStartAddress + SEG_TABLE_SIZE(g_nMaxSegments);

	// init segment table
	SegmentTable tmpTable;
	tmpTable.pFirstRecord = (SegmentRecord*)(g_pSegmentTable + 1);
	tmpTable.nSize = 0;
	memcpy((void*)g_pSegmentTable, (void*)&tmpTable, sizeof(SegmentTable));

	g_vaFirstFree = NULL;

	VA ptr;
	m_malloc(&ptr, 100);

	return 0;
}