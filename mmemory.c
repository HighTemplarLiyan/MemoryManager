///////////////////////////////////////////////////////////////////////////////
// Used abbreviations
///////////////////////////////////////////////////////////////////////////////
// VAS = Virtual Address Space
// va = virtual address
// pa = physical address
// seg = segment
///////////////////////////////////////////////////////////////////////////////


#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#ifndef NO_LOG
#include <signal.h>
#endif

#include "mmemory.h"
#include "logger.h"

///////////////////////////////////////////////////////////////////////////////
// Struct definitions
///////////////////////////////////////////////////////////////////////////////

typedef char* PA;

struct Segment
{
    PA pAddress;

	long nSize;
	bool bIsFree;

	struct Segment* pNext;
	struct Segment* pPrev;

};
typedef struct Segment Segment;

typedef struct
{
    Segment segment;
    
	bool bIsPresent;
	bool bIsAvailable;

} SegmentRecord;

typedef struct
{
	SegmentRecord* pFirstRecord;
	int nSize;
	int nFirstAvailableRecord;

    int nForbiddenSegments[3];

	Segment* pSegListHead;

} SegmentTable;

///////////////////////////////////////////////////////////////////////////////

// explicit casts
#define LONG(x) ((long)(x))
#define RECORD(x) ((SegmentRecord*)(x))

// number of bytes in VA reserved for segment index and offset
#define SEG_INDEX_BYTES   2
#define SEG_OFFSET_BYTES (sizeof(VA) - SEG_INDEX_BYTES)

// used to retrieve segment info from VA
#define GET_VA_SEG_INDEX(va)          (LONG(va) >> (8 * SEG_OFFSET_BYTES))
#define GET_VA_SEG_OFFSET(va)         (LONG(va) & ((1L << (8 * SEG_OFFSET_BYTES)) - 1))

// used to set segment info into VA
#define SET_VA_SEG_INDEX(va, index)   (va = (VA)(GET_VA_SEG_OFFSET(va) | (index << (8 * SEG_OFFSET_BYTES))))
#define SET_VA_SEG_OFFSET(va, offset) (va = (VA)(((GET_VA_SEG_INDEX(va) << (8 * SEG_OFFSET_BYTES)) | offset)))

// handles signed negative integers
// #define GET_VA_SEG_INDEX(va) ((va >> (8 * SEG_OFFSET_BYTES)) & ((0xffL << ((SEG_INDEX_BYTES + 1)*8)) - 1)) 

#define SEG_TABLE_SIZE(records) (sizeof(SegmentTable) + (sizeof(SegmentRecord) * records))

// limits
#define VAS_SIZE_MULTIPLIER 5
#define MAX_SEGMENTS ((2 << (8*SEG_INDEX_BYTES)) - 1)
#define MAX_SEG_SIZE ((2L << (8*SEG_OFFSET_BYTES)) - 1)

///////////////////////////////////////////////////////////////////////////////
// Globals
///////////////////////////////////////////////////////////////////////////////

PA g_pStartAddress = NULL;

size_t g_nCurrentVasSize = 0;
size_t g_nMaxVasSize;

int g_nMaxSegments;
size_t g_nMaxSegmentSize;

SegmentTable* g_pSegTable;

#define GET_SEG_RECORD(va)           (g_pSegTable->pFirstRecord + GET_VA_SEG_INDEX(va))
#define GET_SEG_RECORD_NO(i)         (g_pSegTable->pFirstRecord + i)
#define GET_SEG_RECORD_INDEX(record) ((LONG(record) - LONG(g_pSegTable)) / sizeof(SegmentRecord))

///////////////////////////////////////////////////////////////////////////////

Segment* merge_free_segments(Segment* pFirstSegment, Segment* pSecondSegment)
{
	LOG("Merging free segments:");
	LOG_ADDR("    first:", LONG(pFirstSegment->pAddress));
	LOG_ADDR("    second:", LONG(pSecondSegment->pAddress));

	pFirstSegment->nSize += pSecondSegment->nSize;
	pFirstSegment->pNext = pSecondSegment->pNext;
	if (pSecondSegment->pNext)
        pSecondSegment->pNext->pPrev = pFirstSegment;
        
    free(pSecondSegment);

	return pFirstSegment;
}

Segment* initialize_free_segment(PA pAddress, size_t nSize, Segment* pPrevious, Segment* pNext)
{
    Segment* pFreeSegment = (Segment*)malloc(sizeof(Segment));
    if (!pFreeSegment)
    {
        LOG("Error! Can not initialize free memory segment");
        return NULL;
    }

    pFreeSegment->nSize = nSize;
    pFreeSegment->bIsFree = true;
    pFreeSegment->pAddress = pAddress;

	// link segments
    pFreeSegment->pPrev = pPrevious;
    pFreeSegment->pNext = pNext;

	if (pPrevious)
	{
        if (pPrevious->bIsFree)
            // merge with previous free segment
            pFreeSegment = merge_free_segments(pPrevious, pFreeSegment);
		else
			pPrevious->pNext = pFreeSegment;
	}
	else
        g_pSegTable->pSegListHead = pFreeSegment;

	if (pNext)
	{
        if (pNext->bIsFree)
            // merge with next free segment
            pFreeSegment = merge_free_segments(pFreeSegment, pNext);
		else
			pNext->pPrev = pFreeSegment;
	}

	LOG("Free memory segment initialized:");
	LOG_LONG("\tsize:", pFreeSegment->nSize);
	LOG_ADDR("\taddress:", LONG(pFreeSegment->pAddress));
	LOG_ADDR("\tnext:", LONG(pFreeSegment->pNext ? pFreeSegment->pNext->pAddress : NULL));
    LOG_ADDR("\tprev:", LONG(pFreeSegment->pPrev ? pFreeSegment->pPrev->pAddress : NULL));

	return pFreeSegment;
}

Segment* unload_segment(SegmentRecord* pRecord)
{
    LOG_INT("Unloading segment No.", GET_SEG_RECORD_INDEX(pRecord));
	Segment* pSegmentToUnload = &pRecord->segment;

	// allocate disk memory for segment
	void* pDiskMemory = malloc(pSegmentToUnload->nSize);
	if (!pDiskMemory)
	{
		LOG("Error! Can't allocate disk memory for segment");
		return NULL;
	}

	if (pRecord->bIsPresent)
	{
		// copy segment content to disk memory
		memcpy(pDiskMemory, pSegmentToUnload->pAddress, pSegmentToUnload->nSize);
		// replace segment in memory with free segment
		pSegmentToUnload = initialize_free_segment(pSegmentToUnload->pAddress,
                                                   pSegmentToUnload->nSize,
                                                   pSegmentToUnload->pPrev,
                                                   pSegmentToUnload->pNext);
	}

    // update segment info
    pRecord->segment.pAddress = pDiskMemory;
    pRecord->bIsPresent = false;
    pRecord->segment.pPrev = NULL;
    pRecord->segment.pNext = NULL;

	LOG_ADDR("Segment successfully unloaded with disk memory address:", LONG(pRecord->segment.pAddress));

	return pSegmentToUnload;
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
    LOG_LONG("Searching for free place to load the segment of size:", nSize);

    // try to find free segment, that is large enough
    Segment* pSeg = g_pSegTable->pSegListHead;
	while (pSeg)
	{
        
        if (pSeg->bIsFree)
            LOG("    found segment (free):");
        else
            LOG_INT("    found segment No.", GET_SEG_RECORD_INDEX(RECORD(pSeg)));

		LOG_ADDR("        address:", LONG(pSeg->pAddress));
		LOG_LONG("        size:", pSeg->nSize);
        LOG_INT("        free:", pSeg->bIsFree);
        LOG_ADDR("        next:", LONG(pSeg->pNext ? pSeg->pNext->pAddress : NULL));
        LOG_ADDR("        prev:", LONG(pSeg->pPrev ? pSeg->pPrev->pAddress : NULL));

		if (pSeg->bIsFree && pSeg->nSize >= nSize)
		{
			LOG_ADDR("Found suitable free segment with address:", LONG(pSeg->pAddress));
			return pSeg;
		}

		pSeg = pSeg->pNext;
	}
	LOG("No suitable free segment found");

	if (bForce)
	{
        LOG("Forcing memory allocation");

        // find first not free and not forbidden segment
        pSeg = g_pSegTable->pSegListHead;
        while (pSeg)
        {
            if (!pSeg->bIsFree && !segment_is_forbidden(RECORD(pSeg)))
                break;
            pSeg = pSeg->pNext;
        }

        // find largest segment
        Segment* pLargestSegment = pSeg;
        while (pSeg)
        {
            if (!pSeg->bIsFree && !segment_is_forbidden(RECORD(pSeg)))
            {
                // found segment with suitable size
                if (pSeg->nSize >= nSize)
                    return unload_segment(RECORD(pSeg));
                
                // mark largest found segment
                if (pSeg->nSize > pLargestSegment->nSize)
                    pLargestSegment = pSeg;
            }
            pSeg = pSeg->pNext;
        }

        // unload largest segment found
        if (!pLargestSegment)
        {
            LOG("Cannot deallocate enough memory for segment");
            return NULL;
        }

        LOG_ADDR("Unloading largest:", LONG(pLargestSegment->pAddress));
        Segment* pFreeSeg = unload_segment(RECORD(pLargestSegment));

        // if free memory is still not enough
        // keep unloading following segments
        SegmentRecord* pNextRecord;
        while (pFreeSeg->nSize < nSize && pFreeSeg->pNext)
        {
            pNextRecord = RECORD(pFreeSeg->pNext);
            if (segment_is_forbidden(pNextRecord))
                break;
            pFreeSeg = unload_segment(pNextRecord);
        }

        if (pFreeSeg->nSize >= nSize)
            return pFreeSeg;

        // unload previous segments, if memory is still not enough
        while (pFreeSeg->nSize < nSize && pFreeSeg->pPrev)
        {
            pNextRecord = RECORD(pFreeSeg->pPrev);
            if (segment_is_forbidden(pNextRecord))
                break;
            pFreeSeg = unload_segment(pNextRecord);
        }

        if (pFreeSeg->nSize < nSize)
        {
            LOG("Cannot deallocate enough memory for segment");
            return NULL;
        }

        return pFreeSeg;
	}

	return NULL;
}

bool load_segment_into_memory(SegmentRecord* pRecord, Segment* pFreeSegment)
{
    LOG("Loading segment into memory:");
    LOG_INT("\tsegment No.", GET_SEG_RECORD_INDEX(pRecord));
    LOG_ADDR("\tdestination address:", LONG(pFreeSegment->pAddress));

    Segment* pSegmentToLoad = &pRecord->segment;

    PA pSegmentDiskAddress = pSegmentToLoad->pAddress;
    pSegmentToLoad->pAddress = pFreeSegment->pAddress;

	const size_t nMemoryLeft = pFreeSegment->nSize - pSegmentToLoad->nSize;

    // initialize free segment in the rest of the memory
	if (nMemoryLeft > 0)
	{
		PA pNewFreeSegment = pFreeSegment->pAddress + pSegmentToLoad->nSize;

		initialize_free_segment(pNewFreeSegment,
								nMemoryLeft,
								pSegmentToLoad,
								pFreeSegment->pNext);
    }
    // if no memory left, just link new segment to the next one
	else if (nMemoryLeft == 0)
	{
		pSegmentToLoad->pNext = pFreeSegment->pNext;
		if (pSegmentToLoad->pNext)
			pSegmentToLoad->pNext->pPrev = pSegmentToLoad;
    }
    else
    {
        LOG("Error! Free segment is too small");
        return false;
    }
                    
	// link previous segment to the new one                                                 
    pSegmentToLoad->pPrev = pFreeSegment->pPrev;
	if (pFreeSegment->pPrev)
		pFreeSegment->pPrev->pNext = pSegmentToLoad;
	else
		// set segment list head
		g_pSegTable->pSegListHead = pSegmentToLoad;

	if (!pRecord->bIsPresent && pSegmentDiskAddress)
    {
        LOG("Unloading data to disk memory:");
        LOG_ADDR("   from", LONG(pSegmentDiskAddress));
        LOG_ADDR("   to", LONG(pFreeSegment->pAddress));
        LOG_INT("    size", pSegmentToLoad->nSize);

        // copy segment content into memory
        memcpy(pFreeSegment->pAddress, pSegmentDiskAddress, pSegmentToLoad->nSize);
        // free disk memory
        free(pSegmentDiskAddress);
    }

	pRecord->bIsPresent = true;
    
    free(pFreeSegment);
    
    LOG("Segment has been successfully loaded");
    return true;
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

bool insert_new_record_into_table(size_t nSegmentSize)
{
	LOG("Inserting new record into SegmentTable");

	const size_t nTableSize = g_pSegTable->nSize;

    if (g_pSegTable->nFirstAvailableRecord >= g_nMaxSegments)
    {
        LOG("Error! Can not insert more records");
        return false;
    }

	SegmentRecord* pNewRecord = GET_SEG_RECORD_NO(g_pSegTable->nFirstAvailableRecord);

	pNewRecord->bIsPresent = false;
	pNewRecord->bIsAvailable = false;
    pNewRecord->segment.pAddress = NULL;
    pNewRecord->segment.nSize = nSegmentSize;
	pNewRecord->segment.bIsFree = false;
    pNewRecord->segment.pNext = NULL;
    pNewRecord->segment.pPrev = NULL;


	LOG_INT("Inserted segment memory No.", g_pSegTable->nFirstAvailableRecord);

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

	return true;
}

///////////////////////////////////////////////////////////////////////////////
// Log functions
///////////////////////////////////////////////////////////////////////////////

#ifndef NO_LOG

void log_struct_sizes()
{
	LOG_STR("######################################################################");
	LOG("###### Struct sizes ######");
	LOG_INT("SegmentTable:", sizeof(SegmentTable));
	LOG_INT("SegmentRecord:", sizeof(SegmentRecord));
    LOG_INT("Segment:", sizeof(Segment));
	LOG_STR("######################################################################");
}

void log_memory_dump()
{
    LOG_STR("**********************************************************************");
    LOG("****** Memory dump ******");

    LOG("Segment table:");
    LOG_ADDR("    address:", LONG(g_pSegTable));
    LOG_INT("    records:", g_pSegTable->nSize);

    LOG("Segment records:");
    SegmentRecord* pRecord;
    for (int i = 0; i < g_pSegTable->nSize; ++i)
    {
        pRecord = GET_SEG_RECORD_NO(i);

        LOG_INT("    record No.", i);
        LOG_ADDR("        address:", LONG(pRecord));
        LOG_ADDR("        segment address:", LONG(pRecord->segment.pAddress));
        LOG_INT("        present:", pRecord->bIsPresent);
        LOG_INT("        available:", pRecord->bIsAvailable);
    }

    LOG("Segments:");
    Segment* pSeg = g_pSegTable->pSegListHead;
    while (pSeg)
    {
        if (pSeg->bIsFree)
            LOG("    Segment (free):");
        else
            LOG_INT("    Segment No.", GET_SEG_RECORD_INDEX(RECORD(pSeg)));
        LOG_ADDR("       address:", LONG(pSeg));
        LOG_ADDR("       physical address:", LONG(pSeg->pAddress));
        LOG_LONG("       size:", pSeg->nSize);
        LOG_INT("       free:", pSeg->bIsFree);

        pSeg = pSeg->pNext;
    }

    LOG_STR("**********************************************************************");
}

#endif

///////////////////////////////////////////////////////////////////////////////
// Core functions
///////////////////////////////////////////////////////////////////////////////

int m_malloc(VA* ptr, size_t szBlock)
{
	LOG_LONG("m_malloc: Initializing memory segment of size:", szBlock);

    if (!ptr || szBlock <= 0 || szBlock > g_nMaxSegmentSize)
    {
        LOG("m_malloc: ERROR! Wrong parameters");
        return WRONG_PARAMETERS;
    }

    if (g_nCurrentVasSize + szBlock > g_nMaxVasSize)
    {
        LOG("m_malloc: ERROR! Not enough memory");
        return NOT_ENOUGH_MEMORY;
    }
        
    g_nCurrentVasSize += szBlock;

    const int nSegmentIndex = g_pSegTable->nFirstAvailableRecord;
    if (!insert_new_record_into_table(szBlock))
    {
        LOG("m_malloc: ERROR! Can not insert new record");
        return NOT_ENOUGH_MEMORY;
    }
	SegmentRecord* pNewRecord = GET_SEG_RECORD_NO(nSegmentIndex);

	Segment* pFreeSegment = find_free_place_for_segment(szBlock, false);

    if (!pFreeSegment)
    {
        if (!unload_segment(pNewRecord))
		{
            LOG("m_malloc: ERROR! Can not unload allocated segment");
            return UNKNOWN_ERROR;
        }
    }
    else
    {
        if (!load_segment_into_memory(pNewRecord, pFreeSegment))
        {
            LOG("m_malloc: ERROR! Can not load allocated segment into memory");
            return UNKNOWN_ERROR;
        }
    }

    SET_VA_SEG_INDEX(*ptr, LONG(nSegmentIndex));
    SET_VA_SEG_OFFSET(*ptr, 0L);
    
    LOG("m_malloc: Segment successfully initialized");
	return SUCCESS;
}

int m_free(VA ptr)
{
	const int nSegmentIndex = GET_VA_SEG_INDEX(ptr);
	const long nSegmentOffset = GET_VA_SEG_OFFSET(ptr);

	LOG("m_free: Deallocating memory from segment");
	LOG_INT("        no.", nSegmentIndex);

    if (nSegmentIndex >= g_pSegTable->nSize || nSegmentIndex < 0)
    {
        LOG("m_free: ERROR! Wrong parameters");
        return WRONG_PARAMETERS;
    }

	SegmentRecord* pRecord = GET_SEG_RECORD_NO(nSegmentIndex);

	// TODO: ignore non-zero offset?
	if (pRecord->bIsAvailable || nSegmentOffset != 0)
    {
        LOG("m_free: ERROR! Wrong parameters");
        return WRONG_PARAMETERS;
    }

	if (pRecord->bIsPresent)
	{
		initialize_free_segment(pRecord->segment.pAddress,
								pRecord->segment.nSize,
								pRecord->segment.pPrev,
								pRecord->segment.pNext);
	}
	else
	{
		LOG_ADDR("Deallocating disk memory at:", LONG(pRecord->segment.pAddress));
		free(pRecord->segment.pAddress);
	}

	pRecord->bIsAvailable = true;
	g_nCurrentVasSize -= pRecord->segment.nSize;

	if (g_pSegTable->nFirstAvailableRecord > nSegmentIndex)
		g_pSegTable->nFirstAvailableRecord = nSegmentIndex;

	LOG("m_free: Segment deallocation successful");

	return SUCCESS;
}

int m_read(VA ptr, void* pBuffer, size_t szBuffer)
{
	const int nSegmentIndex = GET_VA_SEG_INDEX(ptr);
	const long nSegmentOffset = GET_VA_SEG_OFFSET(ptr);

	LOG("m_read: Reading from segment");
	LOG_INT("        segment no.", nSegmentIndex);
	LOG_LONG("        offset:", nSegmentOffset);

    if (nSegmentIndex >= g_pSegTable->nSize || nSegmentIndex < 0)
    {
        LOG("m_read: ERROR! Wrong segment index");
        return WRONG_PARAMETERS;
    }

	SegmentRecord* pRecord = GET_SEG_RECORD_NO(nSegmentIndex);

    if (pRecord->bIsAvailable || !pBuffer || szBuffer <= 0)
    {
        LOG("m_read: ERROR! Wrong parameters");
        return WRONG_PARAMETERS;
    }

    if (pRecord->segment.nSize - nSegmentOffset < szBuffer)
    {
        LOG("m_read: ERROR! Reading outside the segment");
        return SEGMENT_VIOLATION;
    }

	// TODO: check size
	if (!pRecord->bIsPresent)
	{
		LOG("Required segment is not present in memory");

        load_adjacent_segments_into_memory(nSegmentIndex);
    }
    
    if (!pRecord->bIsPresent)
    {
        LOG("m_read: ERROR! Can not load required segment into memory");
        return UNKNOWN_ERROR;
    }

	LOG_LONG("Reading from segment to buffer of size:", szBuffer);
	memcpy(pBuffer, pRecord->segment.pAddress + nSegmentOffset, szBuffer);

	LOG("m_read: Reading successfully finished");
	return SUCCESS;
}

int m_write(VA ptr, void* pBuffer, size_t szBuffer)
{
	const int nSegmentIndex = GET_VA_SEG_INDEX(ptr);
	const long nSegmentOffset = GET_VA_SEG_OFFSET(ptr);

	LOG("m_write: Writing into segment");
	LOG_INT("        segment no.", nSegmentIndex);
	LOG_LONG("        offset:", nSegmentOffset);

    if (nSegmentIndex >= g_pSegTable->nSize || nSegmentIndex < 0)
    {
        LOG("m_write: ERROR! Wrong segment index");
        return WRONG_PARAMETERS;
    }

	SegmentRecord* pRecord = GET_SEG_RECORD_NO(nSegmentIndex);

    if (pRecord->bIsAvailable || !pBuffer || szBuffer <= 0)
    {
        LOG("m_write: ERROR! Wrong parameters");
        return WRONG_PARAMETERS;
    }

    if ((pRecord->segment.nSize - nSegmentOffset) < szBuffer)
    {
        LOG("m_write: ERROR! Writing outside the segment");
        return SEGMENT_VIOLATION;
    }

	// TODO: check size
	if (!pRecord->bIsPresent)
	{
        LOG("Required segment is not present in memory");

        load_adjacent_segments_into_memory(nSegmentIndex);
	}

    if (!pRecord->bIsPresent)
    {
        LOG("m_write: ERROR! Can not load required segment into memory");
        return UNKNOWN_ERROR;
    }

	LOG_INT("Writing into segment from buffer of size:", szBuffer);
	memcpy(pRecord->segment.pAddress + nSegmentOffset, pBuffer, szBuffer);

	LOG("m_write: Writing successfully finished");
	return SUCCESS;
}

int m_init(int n, int szPage)
{

#ifndef NO_LOG
    // ensure that log will be written even after program crash
	const int signals[6] = {SIGINT, SIGILL, SIGABRT, SIGFPE, SIGSEGV, SIGTERM};
	for (size_t i = 0; i < 6; ++i)
        assert(signal(signals[i], terminate_logger) != SIG_ERR);
        
    log_struct_sizes();
#endif

    LOG("m_init: Initializing memory manager");
    LOG("            params:");
    LOG_INT("            ", n);
    LOG_INT("            ", szPage);

    if (n <= 0 || szPage <= 0)
    {
        LOG("m_init: ERROR! Wrong parameters");
        return WRONG_PARAMETERS;
    }

    const long nTotalMemory = LONG(n) * szPage;
    const int nSegmentTableSize = SEG_TABLE_SIZE(n);

    g_nMaxSegments = n > MAX_SEGMENTS ? MAX_SEGMENTS : n;
    g_nCurrentVasSize = 0;
    g_nMaxVasSize = nTotalMemory * VAS_SIZE_MULTIPLIER;

    // limit max segment size
    g_nMaxSegmentSize = nTotalMemory;
    // if (g_nMaxSegmentSize > MAX_SEG_SIZE)
    //     g_nMaxSegmentSize = MAX_SEG_SIZE;
    LOG_INT("Max segments:", g_nMaxSegments);
    LOG_LONG("Max segment size:", g_nMaxSegmentSize);

	LOG_LONG("Allocating physical memory (bytes):", nTotalMemory);
    g_pStartAddress = malloc(nTotalMemory);
    if (!g_pStartAddress)
    {
        LOG("m_init: ERROR! Can not allocate enough memory");
        return UNKNOWN_ERROR;
    }

    g_pSegTable = (SegmentTable*)malloc(nSegmentTableSize);
    if (!g_pSegTable)
    {
        LOG("m_init: ERROR! Can not allocate memory for segment table");
        return UNKNOWN_ERROR;
    }
    LOG_ADDR("Segment table address:", LONG(g_pSegTable));
    LOG_INT("Segment table initial size (bytes):", nSegmentTableSize);

    // init segment table
	g_pSegTable->pFirstRecord = RECORD(g_pSegTable + 1);
	g_pSegTable->nSize = 0;
    g_pSegTable->nFirstAvailableRecord = 0;
    g_pSegTable->nForbiddenSegments[0] = g_pSegTable->nForbiddenSegments[1] = g_pSegTable->nForbiddenSegments[2] = -1;
	g_pSegTable->pSegListHead = initialize_free_segment(g_pStartAddress,
                                                        nTotalMemory,
                                                        NULL,
                                                        NULL);

	LOG("m_init: Memory manager initialized successfully");

	return SUCCESS;
}