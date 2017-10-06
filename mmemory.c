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
#include <signal.h>
#include <assert.h>

#include "mmemory.h"
#include "logger.h"

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
	// TODO: size_t
	int nSize;

	Segment* pSegmentListHead;

} SegmentTable;

///////////////////////////////////////////////////////////////////////////////

#define UNKNOWN_ERROR       1
#define SUCCESS             0
#define WRONG_PARAMETERS  (-1)
#define SEGMENT_VIOLATION (-2)
#define NOT_ENOUGH_MEMORY (-2)

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

#define GET_SEG_RECORD(va) (g_pSegmentTable->pFirstRecord + GET_VA_SEG_INDEX(va))

///////////////////////////////////////////////////////////////////////////////

// TODO: merge consequently place free segments
Segment* initialize_free_segment(PA paStartAddress, size_t nSize, Segment* pNextSegment)
{
	Segment freeSegment;
	freeSegment.nSize = nSize;
	freeSegment.bIsFree = true;
	freeSegment.pNextSegment = pNextSegment;

	memcpy(VOID(paStartAddress), VOID(&freeSegment), sizeof(Segment));

	LOG("Initializing free memory segment:");
	LOG_INT("\tsize:", nSize);
	LOG_ADDR("\taddress:", LONG(paStartAddress));

	return (Segment*)paStartAddress;
}

Segment* unload_segment(SegmentRecord* pRecord)
{
	Segment* pSegmentToUnload = &pRecord->segment;

	// allocate disk memory for segment
	void* pDiskMemory = malloc(pSegmentToUnload->nSize);
	if (!pDiskMemory)
		LOG("Error! Can't allocate disk memory for segment");

	Segment* pFreeSegment = NULL;
	if (pRecord->paAddress)
	{
		// copy segment content to disk memory
		memcpy(pDiskMemory, pRecord->paAddress, pSegmentToUnload->nSize);
		// replace segment in memory with free segment
		pFreeSegment = initialize_free_segment(pRecord->paAddress, pSegmentToUnload->nSize, pSegmentToUnload->pNextSegment);
	}

	// update record state
	pRecord->paAddress = pDiskMemory;
	pRecord->bIsPresent = false;
	pSegmentToUnload->pNextSegment = NULL;

	LOG("Segment successfully unloaded");

	return pFreeSegment;
}

Segment* find_free_place_for_segment(size_t nSize, bool bForce)
{
	LOG_INT("Searching for free place to load the segment of size:", nSize);
	Segment* pSegment = g_pSegmentTable->pSegmentListHead;
	while (pSegment)
	{
		LOG("    found segment:");
		LOG_ADDR("        address:", LONG(pSegment));
		LOG_INT("        size:", pSegment->nSize);
		LOG_INT("        free:", pSegment->bIsFree);

		// TODO: choose memory management algorithm: best fit, first fit, etc.
		if (pSegment->bIsFree && pSegment->nSize >= nSize)
		{
			LOG_ADDR("Found free segment with address:", pSegment);
			return pSegment;
		}

		pSegment = pSegment->pNextSegment;
	}
	LOG("No suitable free segment found");

	if (bForce)
	{
		const int nTableSize = g_pSegmentTable->nSize;
		
		// TODO: implement more sophisticated and effective algorithm
		int nSegmentToUnload;
		while (true)
		{
			nSegmentToUnload = nTableSize > 0 ? rand() % nTableSize : 0;
			if (g_pSegmentTable->pFirstRecord[nSegmentToUnload].bIsPresent)
				break;
		}

		LOG_INT("Unloading to disk segment No.", nSegmentToUnload);
		return unload_segment(g_pSegmentTable->pFirstRecord + nSegmentToUnload);
	}

	return NULL;
}

void load_segment_into_memory(SegmentRecord* pRecord, Segment* pFreeSegment)
{
	Segment* pSegmentToPlace = &pRecord->segment;

	// initialize free segment in the rest of the memory
	const size_t nMemoryLeft = pFreeSegment->nSize - pSegmentToPlace->nSize;
	assert(nMemoryLeft >= 0);
	if (nMemoryLeft > 0)
	{
		PA paNextSegment = (char*)pFreeSegment + pSegmentToPlace->nSize;

		Segment* pNewFreeSegment = initialize_free_segment(paNextSegment, nMemoryLeft, pFreeSegment->pNextSegment);
		pSegmentToPlace->pNextSegment = pNewFreeSegment;
	}
	else
		pSegmentToPlace->pNextSegment = pFreeSegment->pNextSegment;

	// link previous segment to the new one
	if ((SegmentRecord*)(g_pSegmentTable + 1) == pRecord)
		g_pSegmentTable->pSegmentListHead = pSegmentToPlace;
	else
		(pRecord - 1)->segment.pNextSegment = pSegmentToPlace;

	// copy segment content into memory
	if (pRecord->paAddress)
		// TODO: free disk memory
		// load segment from disk memory
		memcpy(VOID(pFreeSegment), VOID(pRecord->paAddress), pSegmentToPlace->nSize);
	else
		memset(VOID(pFreeSegment), 0, pSegmentToPlace->nSize);
	pRecord->paAddress = (PA)pFreeSegment;
	pRecord->bIsPresent = true;
	//pSegmentToPlace->bIsFree = false;
	
	LOG("Segment has been successfully loaded");
}

VA insert_new_record_into_table(size_t nSegmentSize)
{
	LOG("Inserting new record into SegmentTable");
	VA vaNewSegmentAddress = 0L;

	const size_t nTableSize = g_pSegmentTable->nSize;

	SET_VA_SEG_INDEX(vaNewSegmentAddress, nTableSize);
	SET_VA_SEG_OFFSET(vaNewSegmentAddress, 0L);

	SegmentRecord* pNewRecord = nTableSize > 0 ? g_pSegmentTable->pFirstRecord + nTableSize : g_pSegmentTable->pFirstRecord;

	SegmentRecord tmpRecord;
	tmpRecord.paAddress = NULL;
	tmpRecord.bIsPresent = false;
	tmpRecord.segment.nSize = nSegmentSize;
	tmpRecord.segment.bIsFree = false;
	tmpRecord.segment.pNextSegment = NULL;

	memcpy(VOID(pNewRecord), VOID(&tmpRecord), sizeof(SegmentRecord));

	LOG_INT("SegmentRecord No.", nTableSize);
	LOG_ADDR("    is loaded into memory address:", pNewRecord);
	LOG_ADDR("    segment VA:", vaNewSegmentAddress);

	g_pSegmentTable->nSize++;

	return vaNewSegmentAddress;
}

void log_size()
{
	LOG_STR("#####################################################");
	LOG("###### Core structs sizes ######");
	LOG_INT("SegmentTable:", sizeof(SegmentTable));
	LOG_INT("SegmentRecord:", sizeof(SegmentRecord));
	LOG_INT("Segment:", sizeof(Segment));
	LOG_STR("#####################################################");
}

///////////////////////////////////////////////////////////////////////////////
// Core functions
///////////////////////////////////////////////////////////////////////////////

int m_malloc(VA* ptr, size_t szBlock)
{
	LOG_INT("m_malloc: Initializing memory segment of size:", szBlock);
	// TODO: check max block size
	if (szBlock < 0)
		return WRONG_PARAMETERS;

	// TODO: check
	if (g_nCurrentVasSize + szBlock > VAS_SIZE)
		return NOT_ENOUGH_MEMORY;

	*ptr = insert_new_record_into_table(szBlock);
	SegmentRecord* pNewRecord = &g_pSegmentTable->pFirstRecord[GET_VA_SEG_INDEX(*ptr)];

	Segment* pFreeSegment = find_free_place_for_segment(szBlock, false);

	if (!pFreeSegment)
	{
		LOG_INT("Unloading to disk NEW segment No.", GET_VA_SEG_INDEX(*ptr));
		unload_segment(pNewRecord);
	}
	else
	{
		LOG("Loading segment into memory:");
		LOG_INT("\tsegment No.", GET_VA_SEG_INDEX(*ptr));
		LOG_ADDR("\tdestination address -", LONG(pFreeSegment));
		load_segment_into_memory(pNewRecord, pFreeSegment);
	}

	return SUCCESS;
}

int m_free(VA ptr)
{
	return SUCCESS;
}

int m_read(VA ptr, void* pBuffer, size_t szBuffer)
{
	return SUCCESS;
}

int m_write(VA ptr, void* pBuffer, size_t szBuffer)
{
	// TODO: check buffer for NULL

	const int nSegmentIndex = GET_VA_SEG_INDEX(ptr);
	const int nSegmentOffset = GET_VA_SEG_OFFSET(ptr);
	LOG("m_write: Writing into segment");
	LOG_INT("        segment No.", nSegmentIndex);
	LOG_INT("        offset:", nSegmentOffset);

	if (nSegmentIndex  >= g_pSegmentTable->nSize || nSegmentIndex < 0)
		return WRONG_PARAMETERS;

	SegmentRecord* pRecord = GET_SEG_RECORD(ptr);

	if (nSegmentOffset >= pRecord->segment.nSize || nSegmentOffset < 0 || szBuffer <= 0)
		return WRONG_PARAMETERS;

	if (pRecord->segment.nSize - nSegmentOffset < szBuffer)
		return SEGMENT_VIOLATION;

	// TODO: check size
	if (!pRecord->bIsPresent)
	{
		LOG("Required segment is not present in memory");
		Segment* pFreeSegment = find_free_place_for_segment(pRecord->segment.nSize, true);
		
		LOG_INT("Loading into memory segment No.", nSegmentIndex);
		load_segment_into_memory(pRecord, pFreeSegment);
	}

	LOG_INT("Writing into segment from buffer of size:", szBuffer);
	memcpy(VOID(pRecord->paAddress + nSegmentOffset), pBuffer, szBuffer);

	LOG("m_write: Writing successfully finished");
	return SUCCESS;
}

int m_init(int n, int szPage)
{

#ifndef NO_LOG
	const int signals[] = {SIGINT, SIGILL, SIGABRT, SIGFPE, SIGSEGV, SIGTERM};
	for (size_t i = 0; i < 6; ++i)
		assert(signal(signals[i], terminate_logger) != SIG_ERR);
#endif

	LOG("m_init: Initializing memory manager");
	log_size();
	// TODO: check max number of segments and their size
	if (n <= 0 || szPage <= 0)
		return WRONG_PARAMETERS;

	// TODO: redundant?
	g_nMaxSegments = n;
	const long nTotalMemory = n * szPage;

	LOG_LONG("Allocating physical memory (bytes):", nTotalMemory);
	g_paStartAddress = malloc(nTotalMemory);
	if (!g_paStartAddress)
		return UNKNOWN_ERROR;

	g_pSegmentTable = (SegmentTable*)g_paStartAddress;
	LOG_ADDR("SegmentTable physical address:", LONG(g_paStartAddress));
	LOG_INT("SegmentTable size (bytes):", SEG_TABLE_SIZE(g_nMaxSegments));
	g_paStartAddress = g_paStartAddress + SEG_TABLE_SIZE(g_nMaxSegments);
	LOG_ADDR("First available physical address:", LONG(g_paStartAddress));

	// init segment table
	SegmentTable tmpTable;
	tmpTable.pFirstRecord = (SegmentRecord*)(g_pSegmentTable + 1);
	tmpTable.nSize = 0;
	tmpTable.pSegmentListHead = initialize_free_segment(g_paStartAddress, nTotalMemory - SEG_TABLE_SIZE(g_nMaxSegments), NULL);
	memcpy(VOID(g_pSegmentTable), VOID(&tmpTable), sizeof(SegmentTable));

	return SUCCESS;
}