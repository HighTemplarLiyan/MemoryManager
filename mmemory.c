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
#include <time.h>

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
	// TODO: size_t (probably not)
	int nSize;
	int nReserved;
	int nFirstAvailableRecord;

    int nForbiddenSegments[3];

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
#define RECORD(x) ((SegmentRecord*)(x))

// number of bytes in VA reserved for segment index and offset
#define SEG_INDEX_BYTES   2
#define SEG_OFFSET_BYTES (sizeof(VA) - SEG_INDEX_BYTES)

#define GET_VA_SEG_INDEX(va)          (LONG(va) >> (8 * SEG_OFFSET_BYTES))
#define GET_VA_SEG_OFFSET(va)         (LONG(va) & ((1L << (8 * SEG_OFFSET_BYTES)) - 1))

#define SET_VA_SEG_INDEX(va, index)   (va = (VA)(GET_VA_SEG_OFFSET(va) | (index << (8 * SEG_OFFSET_BYTES))))
#define SET_VA_SEG_OFFSET(va, offset) (va = (VA)(((GET_VA_SEG_INDEX(va) << (8 * SEG_OFFSET_BYTES)) | offset)))

// handles signed negative integers
// #define GET_VA_SEG_INDEX(va) ((va >> (8 * SEG_OFFSET_BYTES)) & ((0xffL << ((SEG_INDEX_BYTES + 1)*8)) - 1)) 

#define SEG_TABLE_INCREMENT       10
#define SEG_TABLE_SIZE(reserved) (sizeof(SegmentTable) + (sizeof(SegmentRecord) * reserved))

// limits
#define VAS_SIZE     (1000 * 1024 * 1024) // bytes
// TODO: add practical limit
#define MAX_SEGMENTS ((2 << (8*SEG_INDEX_BYTES)) - 1)
#define MAX_SEG_SIZE ((2L << (8*SEG_OFFSET_BYTES)) - 1)
#define MIN_SEG_SIZE (SEG_TABLE_INCREMENT * sizeof(SegmentRecord))

///////////////////////////////////////////////////////////////////////////////
// Globals
///////////////////////////////////////////////////////////////////////////////

PA g_pStartAddress;

size_t g_nCurrentVasSize = 0;
int g_nMaxRecords;

SegmentTable* g_pSegTable;

#define GET_SEG_RECORD(va)           (g_pSegTable->pFirstRecord + GET_VA_SEG_INDEX(va))
#define GET_SEG_RECORD_NO(i)         (g_pSegTable->pFirstRecord + i)
#define GET_SEG_RECORD_INDEX(record) ((LONG(record) - LONG(g_pSegTable)) / sizeof(SegmentRecord))

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

	return pFirstSegment;
}

Segment* initialize_free_segment(PA pAddress, size_t nSize, Segment* pPrevious, Segment* pNext)
{
    // TODO: do some checks (probably not)

	Segment* pFreeSegment = (Segment*)pAddress;

    pFreeSegment->nSize = nSize;
    pFreeSegment->bIsFree = true;

	// link/merge segments
    pFreeSegment->pPrev = pPrevious;
	if (pPrevious)
	{
        if (pPrevious->bIsFree)
            pFreeSegment = merge_free_segments(pPrevious, pFreeSegment);
		else
			pPrevious->pNext = pFreeSegment;
	}
	else
		g_pSegTable->pSegListHead = pFreeSegment;

    pFreeSegment->pNext = pNext;
	if (pNext)
	{
        if (pNext->bIsFree)
            pFreeSegment = merge_free_segments(pFreeSegment, pNext);
		else
			pNext->pPrev = pFreeSegment;
	}

	LOG("Free memory segment initialized:");
	LOG_INT("\tsize:", nSize);
	LOG_ADDR("\taddress:", LONG(pFreeSegment));
	LOG_ADDR("\tnext:", LONG(pFreeSegment->pNext));
	LOG_ADDR("\tprev:", LONG(pFreeSegment->pPrev));

	return pFreeSegment;
}

Segment* unload_segment(SegmentRecord* pRecord)
{
    LOG_INT("Unloading segment No.", GET_SEG_RECORD_INDEX(pRecord));
    LOG_ADDR("  seg record:", LONG(pRecord));
	Segment* pSegmentToUnload = &pRecord->segment;

	// allocate disk memory for segment
	void* pDiskMemory = malloc(pSegmentToUnload->nSize);
	if (!pDiskMemory)
	{
		LOG("Error! Can't allocate disk memory for segment");
		return NULL;
	}

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

bool segment_is_forbidden(const SegmentRecord* pSegRecord)
{
    const int nSegIndex = GET_SEG_RECORD_INDEX(pSegRecord);
    for (int i = 0; i < 3; ++i)
    {
        if (g_pSegTable->nForbiddenSegments[i] == nSegIndex)
            return true;
    }
    return false;
}

Segment* find_free_place_for_segment(size_t nSize, bool bForce)
{
    LOG_INT("Searching for free place to load the segment of size:", nSize);

    // + sizeof(Segment) - ensure that there will be no free segments with size < sizeof(Segment)
    const size_t nSizeWithOffset = nSize + sizeof(Segment);

	Segment* pSeg = g_pSegTable->pSegListHead;
	while (pSeg)
	{
		LOG("    found segment:");
		LOG_ADDR("        address:", LONG(pSeg));
		LOG_INT("        size:", pSeg->nSize);
		LOG_INT("        free:", pSeg->bIsFree);

		if (pSeg->bIsFree && (pSeg->nSize >= nSizeWithOffset || pSeg->nSize == nSize))
		{
			LOG_ADDR("Found suitable free segment with address:", LONG(pSeg));
			return pSeg;
		}

		pSeg = pSeg->pNext;
	}
	LOG("No suitable free segment found");

	if (bForce)
	{
        LOG("Forcing memory deallocation");

        // find first not free and not forbidden segment
        pSeg = g_pSegTable->pSegListHead;
        while (pSeg)
        {
            if (!pSeg->bIsFree && !segment_is_forbidden(RECORD(pSeg)))
                break;
            pSeg = pSeg->pNext;
        }
        assert(pSeg);

        // find largest segment
        Segment* pLargestSegment = pSeg;
        while (pSeg)
        {
            if (!pSeg->bIsFree)
            {
                // found segment with suitable size
                if (pSeg->nSize >= nSizeWithOffset || pSeg->nSize == nSize)
                    return unload_segment(RECORD(pSeg));
                
                // mark largest found segment
                if (pSeg->nSize > pLargestSegment->nSize)
                    pLargestSegment = pSeg;
            }
            pSeg = pSeg->pNext;
        }

        // unload largest segment found
        LOG_ADDR("Unloading largest:", LONG(pLargestSegment));
        Segment* pFreeSeg = unload_segment(RECORD(pLargestSegment));

        // keep unloading following segments
        // TODO: consider segments of equal size
        SegmentRecord* pNextRecord;
        while (pFreeSeg->nSize < nSizeWithOffset && pFreeSeg->nSize != nSize && pFreeSeg->pNext)
        {
            pNextRecord = RECORD(pFreeSeg->pNext);
            if (segment_is_forbidden(pNextRecord))
                break;
            pFreeSeg = unload_segment(pNextRecord);
        }

        if (pFreeSeg->nSize >= nSizeWithOffset || pFreeSeg->nSize == nSize)
            return pFreeSeg;

        // unload previous segments, if memory is still not enough
        while (pFreeSeg->nSize < nSizeWithOffset && pFreeSeg->nSize != nSize && pFreeSeg->pPrev)
        {
            pNextRecord = RECORD(pFreeSeg->pNext);
            if (segment_is_forbidden(pNextRecord))
                break;
            pFreeSeg = unload_segment(pNextRecord);
        }

        if (pFreeSeg->nSize < nSizeWithOffset && pFreeSeg->nSize != nSize)
        {
            LOG("Cannot deallocate enough memory for segment");
            return NULL;
        }

        return pFreeSeg;
	}

	return NULL;
}

void load_segment_into_memory(SegmentRecord* pRecord, Segment* pFreeSegment)
{
    LOG("Loading segment into memory:");
    LOG_INT("\tsegment No.", GET_SEG_RECORD_INDEX(pRecord));
    LOG_ADDR("\tdestination address:", LONG(pFreeSegment));

	Segment* pSegmentToLoad = &pRecord->segment;

	const size_t nMemoryLeft = pFreeSegment->nSize - pSegmentToLoad->nSize;

    // initialize free segment in the rest of the memory
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
		// if no memory left, just link new segment to the next one
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
        // load segment from disk memory
    {
        memcpy(VOID(pFreeSegment), VOID(pRecord->pSegAddress), pSegmentToLoad->nSize);
        free(VOID(pRecord->pSegAddress));
    }
	else // TODO: redundant ???
		memset(VOID(pFreeSegment), 0, pSegmentToLoad->nSize);
	pRecord->pSegAddress = (PA)pFreeSegment;
	pRecord->bIsPresent = true;
	//pSegmentToLoad->bIsFree = false;
	
	LOG("Segment has been successfully loaded");
}

void load_adjacent_segments_into_memory(int nSegmentIndex)
{
    const int segmentsToLoad[3] = {nSegmentIndex, nSegmentIndex - 1, nSegmentIndex + 1};

    LOG("Loading into memory adjacent segments:");
    for (int i = 0; i < 3; ++i)
        LOG_INT("    no.", segmentsToLoad[i]);

    for (int i = 0; i < 3; ++i)
    {
        const int nSegment = segmentsToLoad[i];

        SegmentRecord* pRecord;
        if (nSegment >= 0 && nSegment < g_pSegTable->nSize)
        {
            pRecord = GET_SEG_RECORD_NO(nSegment);
            if (!pRecord->bIsAvailable && !pRecord->bIsPresent)
            {
                // forbid segment from unloading, while loading adjacent ones
                g_pSegTable->nForbiddenSegments[i] = nSegment;

                Segment* pFreeSegment = find_free_place_for_segment(pRecord->segment.nSize, true);
                if (pFreeSegment)
                    load_segment_into_memory(pRecord, pFreeSegment);
            }
        }
    }

    // from now on segments can be unloaded
    for (int i = 0; i < 3; ++i)
        g_pSegTable->nForbiddenSegments[i] = -1;
}

// TODO: prevent table from filling all of the memory
void increase_table_size()
{
	LOG("Increasing segment table size");
	g_pSegTable->nReserved += SEG_TABLE_INCREMENT;
	
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

    // TODO: there is no need to create tmpRecord
	SegmentRecord tmpRecord;
	tmpRecord.pSegAddress = NULL;
	tmpRecord.bIsPresent = false;
	tmpRecord.bIsAvailable = false;
	tmpRecord.segment.nSize = nSegmentSize;
	tmpRecord.segment.bIsFree = false;
	tmpRecord.segment.pNext = NULL;

	memcpy(VOID(pNewRecord), VOID(&tmpRecord), sizeof(SegmentRecord));

	LOG_INT("Segment record No.", g_pSegTable->nFirstAvailableRecord);
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

	if (szBlock < MIN_SEG_SIZE || szBlock > MAX_SEG_SIZE)
		return WRONG_PARAMETERS;

	g_nCurrentVasSize += szBlock;
    if (g_nCurrentVasSize > VAS_SIZE || g_pSegTable->nFirstAvailableRecord >= g_nMaxRecords)
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
		load_segment_into_memory(pNewRecord, pFreeSegment);

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

	SegmentRecord* pRecord = GET_SEG_RECORD(ptr);

	// TODO: ignore non-zero offset?
	if (nSegmentIndex >= g_pSegTable->nSize ||
		nSegmentIndex < 0 ||
		pRecord->bIsAvailable ||
		nSegmentOffset != 0)
		return WRONG_PARAMETERS;

	if (pRecord->bIsPresent)
	{
		initialize_free_segment(pRecord->pSegAddress,
								pRecord->segment.nSize,
								pRecord->segment.pPrev,
								pRecord->segment.pNext);
	}
	else
	{
		LOG("Deallocating disk memory");
		free(pRecord->pSegAddress);
	}

	pRecord->bIsAvailable = true;
	g_nCurrentVasSize -= pRecord->segment.nSize;

	if (g_pSegTable->nFirstAvailableRecord > nSegmentIndex)
		g_pSegTable->nFirstAvailableRecord = nSegmentIndex;

	LOG("m_free: Segment deallocationg successful");

	return SUCCESS;
}

int m_read(VA ptr, void* pBuffer, size_t szBuffer)
{
	const int nSegmentIndex = GET_VA_SEG_INDEX(ptr);
	const int nSegmentOffset = GET_VA_SEG_OFFSET(ptr);

	LOG("m_read: Reading from segment");
	LOG_INT("        segment No.", nSegmentIndex);
	LOG_INT("        offset:", nSegmentOffset);

	if (nSegmentIndex  >= g_pSegTable->nSize || nSegmentIndex < 0)
		return WRONG_PARAMETERS;

	SegmentRecord* pRecord = GET_SEG_RECORD(ptr);

	if (nSegmentOffset >= pRecord->segment.nSize ||
		nSegmentOffset < 0 ||
		pRecord->bIsAvailable ||
		!pBuffer ||
		szBuffer <= 0)
		return WRONG_PARAMETERS;

	if (pRecord->segment.nSize - nSegmentOffset < szBuffer)
		return SEGMENT_VIOLATION;

	// TODO: check size
	if (!pRecord->bIsPresent)
	{
		LOG("Required segment is not present in memory");
        
        load_adjacent_segments_into_memory(nSegmentIndex);
	}

	LOG_INT("Reading from segment to buffer of size:", szBuffer);
	memcpy(pBuffer, VOID(pRecord->pSegAddress + nSegmentOffset), szBuffer);

	LOG("m_write: Reading successfully finished");
	return SUCCESS;
}

int m_write(VA ptr, void* pBuffer, size_t szBuffer)
{
	const int nSegmentIndex = GET_VA_SEG_INDEX(ptr);
	const int nSegmentOffset = GET_VA_SEG_OFFSET(ptr);

	LOG("m_write: Writing into segment");
	LOG_INT("        segment No.", nSegmentIndex);
	LOG_INT("        offset:", nSegmentOffset);

	if (nSegmentIndex  >= g_pSegTable->nSize || nSegmentIndex < 0)
		return WRONG_PARAMETERS;

	SegmentRecord* pRecord = GET_SEG_RECORD(ptr);

	if (nSegmentOffset >= pRecord->segment.nSize ||
		nSegmentOffset < 0 ||
		pRecord->bIsAvailable ||
		!pBuffer ||
		szBuffer <= 0)
		return WRONG_PARAMETERS;

	if ((pRecord->segment.nSize - nSegmentOffset) < szBuffer)
		return SEGMENT_VIOLATION;

	// TODO: check size
	if (!pRecord->bIsPresent)
	{
        LOG("Required segment is not present in memory");

        load_adjacent_segments_into_memory(nSegmentIndex);
	}

	LOG_INT("Writing into segment from buffer of size:", szBuffer);
	memcpy(VOID(pRecord->pSegAddress + nSegmentOffset), pBuffer, szBuffer);

	LOG("m_write: Writing successfully finished");
	return SUCCESS;
}

int m_init(int n, int szPage)
{
	srand(time(NULL));

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
    // limit max amount of records, otherwise SegmentTable may fill all memory
    g_nMaxRecords = ((nTotalMemory / 3) - sizeof(SegmentTable)) / sizeof(SegmentRecord);
    LOG_INT("Max records:", g_nMaxRecords);

	LOG_LONG("Allocating physical memory (bytes):", nTotalMemory);
	g_pStartAddress = malloc(nTotalMemory);
	if (!g_pStartAddress)
		return UNKNOWN_ERROR;

	g_pSegTable = (SegmentTable*)g_pStartAddress;
	const int nTableInitialSize = SEG_TABLE_SIZE(SEG_TABLE_INCREMENT);

	LOG_ADDR("Segment table physical address:", LONG(g_pStartAddress));
	LOG_INT("Segment table initial size (bytes):", nTableInitialSize);

	PA pFirstAvailableAddress = g_pStartAddress + nTableInitialSize;
	LOG_ADDR("First available physical address:", LONG(pFirstAvailableAddress));

    // init segment table
    // TODO: there is no need to create tmpTable
	SegmentTable tmpTable;
	tmpTable.pFirstRecord = (SegmentRecord*)(g_pSegTable + 1);
	tmpTable.nSize = 0;
	tmpTable.nReserved = SEG_TABLE_INCREMENT;
    tmpTable.nFirstAvailableRecord = 0;
    tmpTable.nForbiddenSegments[0] = tmpTable.nForbiddenSegments[1] = tmpTable.nForbiddenSegments[2] = -1;
	tmpTable.pSegListHead = initialize_free_segment(pFirstAvailableAddress,
													nTotalMemory - nTableInitialSize,
													NULL,
													NULL);
	memcpy(VOID(g_pSegTable), VOID(&tmpTable), sizeof(SegmentTable));

	LOG("m_init: Memory manager initialized successfully");

	return SUCCESS;
}