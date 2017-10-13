///////////////////////////////////////////////////////////////////////////////
// Used abbreviations
///////////////////////////////////////////////////////////////////////////////
// VAS = Virtual Address Space
// va = virtual address
// seg = segment
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

	struct Segment* pNext;
	struct Segment* pPrev;

};
typedef struct Segment Segment;

typedef struct
{
	Segment segment;
	PA pSegAddress;
	bool bIsPresent;
	bool bIsAvailable;

} SegmentRecord;

typedef struct
{
	SegmentRecord* pFirstRecord;
	// TODO: size_t
	int nSize;
	int nReserved;
	int nFirstAvailableRecord;

	Segment* pSegListHead;

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
#define SEG_TABLE_INCREMENT 10
#define SEG_TABLE_SIZE(reserved) (sizeof(SegmentTable) + (sizeof(SegmentRecord) * reserved))

///////////////////////////////////////////////////////////////////////////////
// Globals
///////////////////////////////////////////////////////////////////////////////

PA g_pStartAddress;

// TODO: redundant ???
size_t g_nCurrentVasSize = 0;

SegmentTable* g_pSegTable;

#define GET_SEG_RECORD(va) (g_pSegTable->pFirstRecord + GET_VA_SEG_INDEX(va))
#define GET_SEG_RECORD_NO(i) (g_pSegTable->pFirstRecord + i)

///////////////////////////////////////////////////////////////////////////////

Segment* merge_free_segments(Segment* pFirstSegment, Segment* pSecondSegment)
{
	LOG("Merging free segments:");
	LOG_ADDR("    first:", LONG(pFirstSegment));
	LOG_ADDR("    second:", LONG(pSecondSegment));

	pFirstSegment->nSize += pSecondSegment->nSize;
	pFirstSegment->pNext = pSecondSegment->pNext;
	if (pSecondSegment->pNext)
		pSecondSegment->pPrev = pFirstSegment;
	
	// TODO: redundant ???
	memset(pSecondSegment, 0, sizeof(Segment));
	return pFirstSegment;
}

// TODO: handle segments with size < sizeof(Segment)
Segment* initialize_free_segment(PA pAddress, size_t nSize, Segment* pPrevious, Segment* pNext)
{
	// TODO: do some checks (probably not)

	Segment* pFreeSegment = (Segment*)pAddress;

	Segment freeSegment;
	freeSegment.nSize = nSize;
	freeSegment.bIsFree = true;

	// link/merge segments
	freeSegment.pPrev = pPrevious;
	if (pPrevious)
	{
		if (pPrevious->bIsFree)
			pFreeSegment = merge_free_segments(pPrevious, pFreeSegment);
		else
			pPrevious->pNext = pFreeSegment;
	}
	else
		g_pSegTable->pSegListHead = (Segment*)pAddress;

	freeSegment.pNext = pNext;
	if (pNext)
	{
		if (pNext->bIsFree)
			pFreeSegment = merge_free_segments(pFreeSegment, pNext);
		else
			pNext->pPrev = (Segment*)pAddress;
	}

	memcpy(VOID(pFreeSegment), VOID(&freeSegment), sizeof(Segment));

	LOG("Free memory segment initialized:");
	LOG_INT("\tsize:", nSize);
	LOG_ADDR("\taddress:", LONG(pFreeSegment));
	LOG_ADDR("\tnext:", LONG(pNext));
	LOG_ADDR("\tprev:", LONG(pPrevious));

	return pFreeSegment;
}

Segment* unload_segment(SegmentRecord* pRecord)
{
	Segment* pSegmentToUnload = &pRecord->segment;

	// allocate disk memory for segment
	void* pDiskMemory = malloc(pSegmentToUnload->nSize);
	if (!pDiskMemory)
		LOG("Error! Can't allocate disk memory for segment");

	Segment* pFreeSegment = NULL;
	if (pRecord->pSegAddress)
	{
		// copy segment content to disk memory
		memcpy(pDiskMemory, pRecord->pSegAddress, pSegmentToUnload->nSize);
		// replace segment in memory with free segment
		pFreeSegment = initialize_free_segment(pRecord->pSegAddress,
											   pSegmentToUnload->nSize,
											   pSegmentToUnload->pPrev,
											   pSegmentToUnload->pNext);
	}

	// update record state
	pRecord->pSegAddress = pDiskMemory;
	pRecord->bIsPresent = false;
	pSegmentToUnload->pPrev = NULL;
	pSegmentToUnload->pNext = NULL;

	LOG("Segment successfully unloaded");

	return pFreeSegment;
}

Segment* find_free_place_for_segment(size_t nSize, bool bForce)
{
	LOG_INT("Searching for free place to load the segment of size:", nSize);
	Segment* pSegment = g_pSegTable->pSegListHead;
	while (pSegment)
	{
		LOG("    found segment:");
		LOG_ADDR("        address:", LONG(pSegment));
		LOG_INT("        size:", pSegment->nSize);
		LOG_INT("        free:", pSegment->bIsFree);

		// TODO: choose memory management algorithm: best fit, first fit, etc.
		if (pSegment->bIsFree && pSegment->nSize >= nSize)
		{
			LOG_ADDR("Found suitable free segment with address:", LONG(pSegment));
			return pSegment;
		}

		pSegment = pSegment->pNext;
	}
	LOG("No suitable free segment found");

	if (bForce)
	{
		const int nTableSize = g_pSegTable->nSize;
		
		// TODO: implement more sophisticated and effective algorithm
		// TODO: check unloaded block size
		int nSegmentToUnload;
		while (true)
		{
			// select random segment to unload
			nSegmentToUnload = nTableSize > 0 ? rand() % nTableSize : 0;
			if (g_pSegTable->pFirstRecord[nSegmentToUnload].bIsPresent)
				break;
		}

		LOG_INT("Unloading to disk the segment No.", nSegmentToUnload);
		return unload_segment(g_pSegTable->pFirstRecord + nSegmentToUnload);
	}

	return NULL;
}

void load_segment_into_memory(SegmentRecord* pRecord, Segment* pFreeSegment)
{
	Segment* pSegmentToLoad = &pRecord->segment;

	// initialize free segment in the rest of the memory
	const size_t nMemoryLeft = pFreeSegment->nSize - pSegmentToLoad->nSize;
	assert(nMemoryLeft >= 0);
	if (nMemoryLeft > 0)
	{
		PA pNewFreeSegment = (char*)pFreeSegment + pSegmentToLoad->nSize;

		initialize_free_segment(pNewFreeSegment,
								nMemoryLeft,
								pSegmentToLoad,
								pFreeSegment->pNext);
	}
	else
	{
		// if no memory left, just new segment to the next one
		pSegmentToLoad->pNext = pFreeSegment->pNext;
		if (pSegmentToLoad->pNext)
			pSegmentToLoad->pNext->pPrev = pSegmentToLoad;
	}

	// link previous segment to the new one
	pSegmentToLoad->pPrev = pFreeSegment->pPrev;
	if (pFreeSegment->pPrev)
		pFreeSegment->pPrev->pNext = pSegmentToLoad;
	else
		// set segment list head
		g_pSegTable->pSegListHead = pSegmentToLoad;

	// copy segment content into memory
	if (pRecord->pSegAddress)
		// TODO: free disk memory
		// load segment from disk memory
		memcpy(VOID(pFreeSegment), VOID(pRecord->pSegAddress), pSegmentToLoad->nSize);
	else
		memset(VOID(pFreeSegment), 0, pSegmentToLoad->nSize);
	pRecord->pSegAddress = (PA)pFreeSegment;
	pRecord->bIsPresent = true;
	//pSegmentToLoad->bIsFree = false;
	
	LOG("Segment has been successfully loaded");
}

// TODO: set minimum segment sizes
// TODO: prevent table from filling all of the memory
void increase_table_size()
{
	LOG("Increasing segment table size");
	g_pSegTable->nReserved += SEG_TABLE_INCREMENT;
	
	// TODO: unload more than one segment (can be avoided by setting min segment size)
	Segment* pFirstSegment = g_pSegTable->pSegListHead;
	if (!pFirstSegment->bIsFree)
	{
		for (int i = 0; i < g_pSegTable->nSize; ++i)
		{
			SegmentRecord* pRecord = GET_SEG_RECORD_NO(i);
			// unload first segment in memory if it is not free
			if (&(pRecord->segment) == pFirstSegment)
			{
				pFirstSegment = unload_segment(pRecord);
				break;
			}
		}
	}

	// cutting piece of memory from first segment
	PA pNewFreeSegment = g_pStartAddress + SEG_TABLE_SIZE(g_pSegTable->nReserved);
	const size_t nNewSize = pFirstSegment->nSize - (LONG(pNewFreeSegment) - LONG(pFirstSegment));

	g_pSegTable->pSegListHead = initialize_free_segment(pNewFreeSegment,
														nNewSize,
														NULL,
														pFirstSegment->pNext);
}

// TODO: check max records
VA insert_new_record_into_table(size_t nSegmentSize)
{
	LOG("Inserting new record into SegmentTable");
	VA vaNewSegmentAddress = 0L;

	const size_t nTableSize = g_pSegTable->nSize;

	SET_VA_SEG_INDEX(vaNewSegmentAddress, LONG(g_pSegTable->nFirstAvailableRecord));
	SET_VA_SEG_OFFSET(vaNewSegmentAddress, 0L);

	// reserve space for table records if it exceeds
	if (g_pSegTable->nFirstAvailableRecord >= g_pSegTable->nReserved)
		increase_table_size();

	SegmentRecord* pNewRecord = GET_SEG_RECORD(vaNewSegmentAddress);

	SegmentRecord tmpRecord;
	tmpRecord.pSegAddress = NULL;
	tmpRecord.bIsPresent = false;
	tmpRecord.bIsAvailable = false;
	tmpRecord.segment.nSize = nSegmentSize;
	tmpRecord.segment.bIsFree = false;
	tmpRecord.segment.pNext = NULL;

	memcpy(VOID(pNewRecord), VOID(&tmpRecord), sizeof(SegmentRecord));

	LOG_INT("SegmentRecord No.", g_pSegTable->nFirstAvailableRecord);
	LOG_ADDR("    is loaded into memory address:", LONG(pNewRecord));
	LOG_ADDR("    segment VA:", LONG(vaNewSegmentAddress));

	if (g_pSegTable->nFirstAvailableRecord == g_pSegTable->nSize)
		g_pSegTable->nSize++;

	// find place to load next record
	bool bFoundAvailable = false;
	for (int i = g_pSegTable->nFirstAvailableRecord + 1; i < nTableSize; ++i)
		if (GET_SEG_RECORD_NO(i)->bIsAvailable)
		{
			g_pSegTable->nFirstAvailableRecord = i;
			bFoundAvailable = true;
			break;
		}
	if (!bFoundAvailable)
		g_pSegTable->nFirstAvailableRecord = g_pSegTable->nSize;

	LOG_INT("Table size:", g_pSegTable->nSize);
	LOG_INT("Next record will have index", g_pSegTable->nFirstAvailableRecord);

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
	// TODO: check max and min block size
	if (szBlock < 0)
		return WRONG_PARAMETERS;

	// TODO: check
	if (g_nCurrentVasSize + szBlock > VAS_SIZE)
		return NOT_ENOUGH_MEMORY;

	*ptr = insert_new_record_into_table(szBlock);
	SegmentRecord* pNewRecord = GET_SEG_RECORD(*ptr);

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
	const int nSegmentIndex = GET_VA_SEG_INDEX(ptr);
	const int nSegmentOffset = GET_VA_SEG_OFFSET(ptr);

	LOG("m_free: Deallocating memory from segment");
	LOG_ADDR("        VA:", LONG(ptr));

	if (nSegmentIndex >= g_pSegTable->nSize || nSegmentIndex < 0)
		return WRONG_PARAMETERS;

	// TODO: ignore non-zero offset?
	if (nSegmentIndex >= g_pSegTable->nSize ||
		nSegmentIndex < 0 ||
		nSegmentOffset != 0)
		return WRONG_PARAMETERS;

	SegmentRecord* pRecord = GET_SEG_RECORD(ptr);

	if (pRecord->bIsPresent)
	{
		// TODO: restore segment list integrity
		initialize_free_segment(pRecord->pSegAddress,
								pRecord->segment.nSize,
								pRecord->segment.pPrev,
								pRecord->segment.pNext);
	}
	else
	{
		LOG("Deallocating disk memory from segment");
		free(pRecord->pSegAddress);
	}

	pRecord->bIsAvailable = true;

	if (g_pSegTable->nFirstAvailableRecord > nSegmentIndex)
		g_pSegTable->nFirstAvailableRecord = nSegmentIndex;

	LOG("m_free: Segment deallocationg successful");

	return SUCCESS;
}

int m_read(VA ptr, void* pBuffer, size_t szBuffer)
{
	// TODO: check buffer for NULL

	const int nSegmentIndex = GET_VA_SEG_INDEX(ptr);
	const int nSegmentOffset = GET_VA_SEG_OFFSET(ptr);
	LOG("m_read: Reading from segment");
	LOG_INT("        segment No.", nSegmentIndex);
	LOG_INT("        offset:", nSegmentOffset);

	if (nSegmentIndex  >= g_pSegTable->nSize || nSegmentIndex < 0)
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

	LOG_INT("Reading from segment to buffer of size:", szBuffer);
	memcpy(pBuffer, VOID(pRecord->pSegAddress + nSegmentOffset), szBuffer);

	LOG("m_write: Reading successfully finished");
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

	if (nSegmentIndex  >= g_pSegTable->nSize || nSegmentIndex < 0)
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
	memcpy(VOID(pRecord->pSegAddress + nSegmentOffset), pBuffer, szBuffer);

	LOG("m_write: Writing successfully finished");
	return SUCCESS;
}

int m_init(int n, int szPage)
{

#ifndef NO_LOG
	const int signals[6] = {SIGINT, SIGILL, SIGABRT, SIGFPE, SIGSEGV, SIGTERM};
	for (size_t i = 0; i < 6; ++i)
		assert(signal(signals[i], terminate_logger) != SIG_ERR);
#endif

	LOG("m_init: Initializing memory manager");
	log_size();

	if (n <= 0 || szPage <= 0)
		return WRONG_PARAMETERS;

	const long nTotalMemory = n * szPage;

	LOG_LONG("Allocating physical memory (bytes):", nTotalMemory);
	g_pStartAddress = malloc(nTotalMemory);
	if (!g_pStartAddress)
		return UNKNOWN_ERROR;

	g_pSegTable = (SegmentTable*)g_pStartAddress;
	const int nTableInitialSize = SEG_TABLE_SIZE(SEG_TABLE_INCREMENT);

	LOG_ADDR("SegmentTable physical address:", LONG(g_pStartAddress));
	LOG_INT("SegmentTable size (bytes):", nTableInitialSize);

	PA pFirstAvailableAddress = g_pStartAddress + nTableInitialSize;
	LOG_ADDR("First available physical address:", LONG(pFirstAvailableAddress));

	// init segment table
	SegmentTable tmpTable;
	tmpTable.pFirstRecord = (SegmentRecord*)(g_pSegTable + 1);
	tmpTable.nSize = 0;
	tmpTable.nReserved = SEG_TABLE_INCREMENT;
	tmpTable.nFirstAvailableRecord = 0;
	tmpTable.pSegListHead = initialize_free_segment(pFirstAvailableAddress,
													nTotalMemory - nTableInitialSize,
													NULL,
													NULL);
	memcpy(VOID(g_pSegTable), VOID(&tmpTable), sizeof(SegmentTable));

	LOG("m_init: Memory manager initialized successfully");

	return SUCCESS;
}