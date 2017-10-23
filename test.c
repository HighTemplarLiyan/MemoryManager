#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "CUnit/Basic.h"
#include "mmemory.h"
#include "logger.h"

#define NO_LOG

#define KB(n) (1024 * (n))
#define MB(n) (1024 * KB(n))
#define GB(n) (1024 * MB(n))

int init_suite()
{
    INIT_LOGGER("test_log.txt");
    return 0;
}

int clean_suite()
{
    TERMINATE_LOGGER(0);
    return 0;
}

void test_init()
{
    CU_ASSERT(
        m_init(-1, KB(100)) == WRONG_PARAMETERS
    );
    CU_ASSERT(
        m_init(0, 0) == WRONG_PARAMETERS
    );
    CU_ASSERT(
        m_init(-100, -100) == WRONG_PARAMETERS
    );
    
    // too large memory block
    CU_ASSERT(
        m_init(10, GB(1)) == UNKNOWN_ERROR
    );

    CU_ASSERT(
        m_init(1, 1) == SUCCESS
    );
    m_terminate();
    CU_ASSERT(
        m_init(10, MB(10)) == SUCCESS
    );
    m_terminate();
    CU_ASSERT(
        m_init(1000, KB(100)) == SUCCESS
    );
    m_terminate();
    /*
    CU_ASSERT(
        m_init(4, MB(512)) == SUCCESS
    );
    */
}

void test_malloc()
{
    m_init(10, MB(1));
    
    CU_ASSERT(
        m_malloc(NULL, KB(100)) == WRONG_PARAMETERS
    );

    VA pPtr;
    CU_ASSERT(
        m_malloc(&pPtr, 0) == WRONG_PARAMETERS
    );
    CU_ASSERT(
        m_malloc(&pPtr, -1) == WRONG_PARAMETERS
    );

    // too big
    CU_ASSERT(
        m_malloc(&pPtr, MB(10) + KB(1)) == WRONG_PARAMETERS
    );

    for (int i = 0; i < 10; ++i)
        CU_ASSERT(
            m_malloc(&pPtr, 1) == SUCCESS
        );
    
    // max segments limit is reached
    CU_ASSERT(
        m_malloc(&pPtr, 1) == NOT_ENOUGH_MEMORY
    );
    
    m_terminate();

    ////////////////////////////////////////////////////////

    m_init(10, MB(1));

    const int nVasSizeMultiplier = 10;
    for (int i = 0; i < nVasSizeMultiplier; ++i)
        CU_ASSERT(
            m_malloc(&pPtr, MB(10)) == SUCCESS
        );

    // virtual address space overflow
    CU_ASSERT(
        m_malloc(&pPtr, KB(1)) == NOT_ENOUGH_MEMORY
    );

    m_terminate();
}

void test_free()
{
    m_init(10, MB(1));
    
    VA pPtr;
    m_malloc(&pPtr, KB(100));

    // non-zero offset
    CU_ASSERT(
        m_free(pPtr + 100) == WRONG_PARAMETERS
    );

    CU_ASSERT(
        m_free(pPtr) == SUCCESS
    );

    // double free
    CU_ASSERT(
        m_free(pPtr) == WRONG_PARAMETERS
    );

    for (int i = 0; i < 9; ++i)
        m_malloc(&pPtr, MB(1));
    
    // segment is unloaded into disk memory
    m_malloc(&pPtr, MB(1));
    CU_ASSERT(
        m_free(pPtr) == SUCCESS
    );

    m_terminate();
}

char buf1[] = "Segment No.0, offset - 0";
char buf2[] = "Segment No.1, offset - 1024";
char buf3[] = "Segment No.3, offset - 0";

VA g_Ptr1;
VA g_Ptr2;
VA g_Ptr3;

void test_write()
{
    m_init(10, MB(10) / 10);

    CU_ASSERT(
        m_write(NULL, buf1, sizeof(buf1)) == WRONG_PARAMETERS
    );

    m_malloc(&g_Ptr1, KB(10));
    CU_ASSERT(
        m_write(g_Ptr1, NULL, 0) == WRONG_PARAMETERS
    );
    CU_ASSERT(
        m_write(g_Ptr1 + KB(10) - 10, buf1, sizeof(buf1)) == SEGMENT_VIOLATION
    );
    
    // write without offset
    CU_ASSERT(
        m_write(g_Ptr1, buf1, sizeof(buf1)) == SUCCESS
    );

    m_malloc(&g_Ptr2, KB(10));
    // write with offset
    CU_ASSERT(
        m_write(g_Ptr2 + KB(1), buf2, sizeof(buf2)) == SUCCESS
    );

    m_malloc(&g_Ptr3, KB(512));
    // segment is unloaded into disk memory
    m_malloc(&g_Ptr3, KB(512));
    // write to unloaded segment
    CU_ASSERT(
        m_write(g_Ptr3, buf3, sizeof(buf3)) == SUCCESS
    );
}

void test_read()
{
    CU_ASSERT(m_read(g_Ptr1, NULL, 0) == WRONG_PARAMETERS);
    
    char* buf = (char*)malloc(sizeof(buf3));
    // read from segment, that is present in the memory
    CU_ASSERT(
        (m_read(g_Ptr3, buf, sizeof(buf3)) == SUCCESS)
        && 
        (strcmp(buf, buf3) == 0)
    );
    free(buf);

    buf = (char*)malloc(sizeof(buf1));
    // read from unloaded segment
    CU_ASSERT(
        (m_read(g_Ptr2 + KB(1), buf, sizeof(buf2)) == SUCCESS)
        &&
        (strcmp(buf, buf2) == 0)
    );

    m_terminate();
}

void stress_test()
{
    FILE* file;
    
    file = fopen("test.csv", "w");
    if (!file)
        return;

    char buf = 'c';
    const int nWriteOperations = 100;

    const int nMaxSegments = 100;
    const int nMaxSegmentSize = nMaxSegments * KB(100);

    const int nNumberOfTests = 100;
    const int nSegSizeIncrement = (nMaxSegmentSize - 1) / nNumberOfTests;

    // store segment address
    VA* segmentAddress = (VA*)malloc(nMaxSegments * sizeof(VA));
    // store average size diffs
    long* sizeDifference = (long*)malloc(nNumberOfTests * sizeof(long));
    // store average fragmentation
    double* fragmentation = (double*)malloc(nNumberOfTests * sizeof(double));

    for (int test = 0; test < nNumberOfTests; ++test)
    {
        m_init(nMaxSegments, nMaxSegmentSize / nMaxSegments);

        const int nMaxSegSizeDifference = nSegSizeIncrement * test;

        // allocate random-sized segments
        for (int i = 0; i < nMaxSegments; ++i)
        {
            const int nSegSize = rand() % (1 + nMaxSegSizeDifference) + 1;
            assert(m_malloc(&segmentAddress[i], nSegSize) == SUCCESS);
        }

        double averageFragmentation = 0;

        // perform random write operations
        for (int i = 0; i < nWriteOperations; ++i)
        {
            const int nSegment = rand() % nMaxSegments;
            m_write(segmentAddress[nSegment], &buf, sizeof(buf));
            
            averageFragmentation += calculate_fragmentation();
        }

        sizeDifference[test] = calculate_average_seg_size_difference();
        fragmentation[test] = averageFragmentation / nNumberOfTests;

        m_terminate();
    }

    for (int test = 0; test < nNumberOfTests; ++test)
        fprintf(file, "%ld;", sizeDifference[test]);
    fprintf(file, "%s", "\n");
    for (int test = 0; test < nNumberOfTests; ++test)
        fprintf(file, "%lf;", fragmentation[test]);

    free(segmentAddress);
    fclose(file);
}

int main()
{
    srand(time(NULL));

    CU_pSuite pSuite = NULL;
    
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    pSuite = CU_add_suite("Memory manager suite", init_suite, clean_suite);
    if (NULL == pSuite)
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (
        (NULL == CU_add_test(pSuite, "test of m_init()", test_init)) ||
        (NULL == CU_add_test(pSuite, "test of m_malloc()", test_malloc)) ||
        (NULL == CU_add_test(pSuite, "test of m_free()", test_free)) ||
        (NULL == CU_add_test(pSuite, "test of m_write()", test_write)) ||
        (NULL == CU_add_test(pSuite, "test of m_read()", test_read))
       )
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();

    INIT_LOGGER("tst.txt");
    //stress_test();
    TERMINATE_LOGGER(0);

    return CU_get_error();
}