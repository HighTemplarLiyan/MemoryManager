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
	bool bIsPresent;

} SegmentRecord;

typedef struct
{
	SegmentRecord* pFirstRecord;
	int nSize;

	//Segment* pSegmentListHead;

} SegmentTable;

///////////////////////////////////////////////////////////////////////////////

#define VAS_SIZE (1000 * 1024 * 1024) // MB
#define SEG_TABLE_SIZE(MAX_SEGMENTS) (sizeof(SegmentTable) + sizeof(SegmentRecord) * MAX_SEGMENTS)

// number of bytes in VA reserved for segment index and offset
#define SEG_INDEX_BYTES 2
#define SEG_OFFSET_BYTES (sizeof(VA) - SEG_INDEX_BYTES)

#define GET_VA_SEG_INDEX(va)          (va >> (8 * SEG_OFFSET_BYTES))
#define GET_VA_SEG_OFFSET(va)         (va & ((1L << (8 * SEG_OFFSET_BYTES)) - 1))

#define SET_VA_SEG_INDEX(va, index)   (va = GET_VA_SEG_OFFSET(va) | (index << (8 * SEG_OFFSET_BYTES)))
#define SET_VA_SEG_OFFSET(va, offset) (va = ((GET_VA_SEG_INDEX(va) << (8 * SEG_OFFSET_BYTES)) | offset))

// handles signed negative integers
// #define GET_VA_SEG_INDEX(va) ((va >> (8 * SEG_OFFSET_BYTES)) & ((0xffL << ((SEG_INDEX_BYTES + 1)*8)) - 1)) 

// globals

void* g_paStartAddress;

VA g_vaFirstFree = NULL;
const VA g_vaLastAvailable = NULL + VAS_SIZE / sizeof(VA) - 1;

SegmentTable* g_pSegmentTable;
int g_nMaxSegments;

///////////////////////////////////////////////////////////////////////////////

SegmentRecord* insert_new_record_into_table(VA vaSegmentAddress, size_t nSegmentSize)
{
	size_t nTableSize = g_pSegmentTable->nSize;

	SegmentRecord* pNewRecord = g_pSegmentTable->pFirstRecord + nTableSize;

	SegmentRecord tmpRecord;
	tmpRecord.pAddress = NULL;
	tmpRecord.bIsPresent = false;
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