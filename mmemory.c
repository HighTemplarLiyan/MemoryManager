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

///////////////////////////////////////////////////////////////////////////////
// Struct definitions
///////////////////////////////////////////////////////////////////////////////

typedef char* PA;

struct Segment
{
	long nSize;
	bool bIsFree;
	struct Segment* pNextSegment;

};
typedef struct Segment Segment;

typedef struct
{
	Segment segment;
	PA paAddress;
	bool bIsPresent;

} SegmentRecord;

typedef struct
{
	SegmentRecord* pFirstRecord;
	int nSize;

	Segment* pSegmentListHead;

} SegmentTable;

///////////////////////////////////////////////////////////////////////////////

#define LONG(x) ((long)(x))
#define VOID(x) ((void*)(x))

// number of bytes in VA reserved for segment index and offset
#define SEG_INDEX_BYTES 2
#define SEG_OFFSET_BYTES (sizeof(VA) - SEG_INDEX_BYTES)

#define GET_VA_SEG_INDEX(va)          (LONG(va) >> (8 * SEG_OFFSET_BYTES))
#define GET_VA_SEG_OFFSET(va)         (LONG(va) & ((1L << (8 * SEG_OFFSET_BYTES)) - 1))

#define SET_VA_SEG_INDEX(va, index)   (va = (VA)(GET_VA_SEG_OFFSET(va) | (index << (8 * SEG_OFFSET_BYTES))))
#define SET_VA_SEG_OFFSET(va, offset) (va = (VA)(((GET_VA_SEG_INDEX(va) << (8 * SEG_OFFSET_BYTES)) | offset)))

// handles signed negative integers
// #define GET_VA_SEG_INDEX(va) ((va >> (8 * SEG_OFFSET_BYTES)) & ((0xffL << ((SEG_INDEX_BYTES + 1)*8)) - 1)) 

#define VAS_SIZE (1000 * 1024 * 1024) // bytes
#define MAX_SEGMENTS ((2 << (8*SEG_INDEX_BYTES)) - 1)
#define SEG_TABLE_SIZE(MAX_SEGMENTS) (sizeof(SegmentTable) + (sizeof(SegmentRecord) * MAX_SEGMENTS))

///////////////////////////////////////////////////////////////////////////////
// Globals
///////////////////////////////////////////////////////////////////////////////

PA g_paStartAddress;

size_t g_nCurrentVasSize = 0;

SegmentTable* g_pSegmentTable;
int g_nMaxSegments;

///////////////////////////////////////////////////////////////////////////////

Segment* initialize_free_segment(PA paStartAddress, size_t nSize, Segment* pNextSegment)
{
	Segment freeSegment;
	freeSegment.nSize = nSize - sizeof(Segment);
	freeSegment.bIsFree = true;
	freeSegment.pNextSegment = pNextSegment;

	memcpy(VOID(paStartAddress), VOID(&freeSegment), sizeof(Segment));

	return (Segment*)paStartAddress;
}

bool place_segment_into_memory(SegmentRecord* pRecord)
{
	Segment* pSegmentToPlace = &(pRecord->segment);

	Segment* pSegment = g_pSegmentTable->pSegmentListHead;
	Segment* pPreviousSegment = NULL;
	Segment* pNextSegment = NULL;

	while (pSegment)
	{
		pNextSegment = pSegment->pNextSegment;

		// TODO: choose memory management algorithm: best fit, first fit, etc.
		if (pSegment->bIsFree && pSegment->nSize >= pSegmentToPlace->nSize)
		{
			// initialize free segment in the rest of the memory
			size_t nMemoryLeft = pSegment->nSize - pSegmentToPlace->nSize;
			if (nMemoryLeft > 0)
			{
				PA paNextSegment = (char*)(pSegment + 1) + pSegment->nSize;

				Segment* pNewFreeSegment = initialize_free_segment(paNextSegment, nMemoryLeft, pNextSegment);
				pSegmentToPlace->pNextSegment = pNewFreeSegment;
			}
			else
				pSegmentToPlace->pNextSegment = pNextSegment;

			// clear previous free segment record
			//memset((void*)pSegment, 0, sizeof(Segment));

			if (pPreviousSegment)
				pPreviousSegment->pNextSegment = pSegmentToPlace;
			else
				// if segment is inserted into the beggining of memory
				g_pSegmentTable->pSegmentListHead = pSegmentToPlace;

			// copy segment content into memory
			// TODO: bIsPresent assert
			// TODO: move to separate function
			if (pRecord->paAddress)
				memcpy(VOID(pSegment), VOID(pRecord->paAddress), pSegmentToPlace->nSize);
			else
				memset(VOID(pSegment), 0, pSegmentToPlace->nSize);
			pRecord->paAddress = (PA)pSegment;
			pRecord->bIsPresent = true;
			
			return true;
		}

		pPreviousSegment = pSegment;
		pSegment = pNextSegment;
	}

	return false;
}

VA insert_new_record_into_table(size_t nSegmentSize)
{
	VA vaNewSegmentAddress = 0L;

	size_t nTableSize = g_pSegmentTable->nSize;

	SET_VA_SEG_INDEX(vaNewSegmentAddress, nTableSize);
	SET_VA_SEG_OFFSET(vaNewSegmentAddress, 0L);

	SegmentRecord* pNewRecord = g_pSegmentTable->pFirstRecord + nTableSize;

	SegmentRecord tmpRecord;
	tmpRecord.paAddress = NULL;
	tmpRecord.bIsPresent = false;
	tmpRecord.segment.nSize = nSegmentSize;
	tmpRecord.segment.pNextSegment = NULL;

	memcpy(VOID(pNewRecord), VOID(&tmpRecord), sizeof(SegmentRecord));

	g_pSegmentTable->nSize++;

	return vaNewSegmentAddress;
}

int m_malloc(VA* ptr, size_t szBlock)
{
	// TODO: check max block size
	if (szBlock < 0)
		return -1;

	if (g_nCurrentVasSize + szBlock > VAS_SIZE)
		return -2;

	*ptr = insert_new_record_into_table(szBlock);
	place_segment_into_memory(&g_pSegmentTable->pFirstRecord[GET_VA_SEG_INDEX(ptr)]);

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
	// TODO: check max number of segments and their size
	if (n <= 0 || szPage <= 0)
		return -1;

	// TODO: redundant?
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
	tmpTable.pSegmentListHead = initialize_free_segment(g_paStartAddress, nTotalMemory, NULL);
	memcpy(VOID(g_pSegmentTable), VOID(&tmpTable), sizeof(SegmentTable));

	return 0;
}