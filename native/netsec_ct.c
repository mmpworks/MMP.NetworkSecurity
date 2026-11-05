/* See netsec_ct.h. The portability compile in native/build.cmd sets no NSCT_BUILD, so this file sets it. */
#ifndef NSCT_BUILD
#define NSCT_BUILD
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "netsec_ct.h"

typedef int (NSCT_CALL *nsct_compare_fn)(const unsigned char *a, const unsigned char *b, unsigned int n);

NSCT_API unsigned int NSCT_CALL nsct_abi_version(void)
{
    return NSCT_ABI_VERSION;
}

NSCT_API int NSCT_CALL nsct_compare_leaky(const unsigned char *a, const unsigned char *b, unsigned int n)
{
    unsigned int i;
    if (a == 0 || b == 0) return NSCT_ERR_ARGUMENT;
    for (i = 0; i < n; i++)
    {
        if (a[i] != b[i]) return 1; /* The early return is the leak this lesson measures. */
    }
    return 0;
}

NSCT_API int NSCT_CALL nsct_compare_ct(const unsigned char *a, const unsigned char *b, unsigned int n)
{
    volatile unsigned char diff = 0; /* volatile keeps every byte read in the loop. The result still depends on the optimizer. */
    unsigned int i;
    if (a == 0 || b == 0) return NSCT_ERR_ARGUMENT;
    for (i = 0; i < n; i++)
    {
        diff = (unsigned char)(diff | (a[i] ^ b[i]));
    }
    /* diff + 255 reaches bit 8 for every nonzero diff, so this gives 0 or 1 with no branch. */
    return (int)(((unsigned int)diff + 0xFFu) >> 8);
}

NSCT_API int NSCT_CALL nsct_sample(int which, const unsigned char *a, const unsigned char *b, unsigned int n,
                                   unsigned int *out_ticks, unsigned int samples, unsigned int *out_freq)
{
    LARGE_INTEGER freq, start, stop;
    nsct_compare_fn volatile chosen; /* The volatile read below stops the compiler from inlining the compare. */
    nsct_compare_fn compare;
    volatile int sink = 0;           /* The volatile write keeps the compare's result in use. */
    unsigned int i;

    if (a == 0 || b == 0 || out_ticks == 0 || out_freq == 0) return NSCT_ERR_ARGUMENT;
    if (which == NSCT_WHICH_LEAKY) chosen = nsct_compare_leaky;
    else if (which == NSCT_WHICH_CONSTANT_TIME) chosen = nsct_compare_ct;
    else return NSCT_ERR_WHICH;

    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart <= 0 || freq.QuadPart > 0xFFFFFFFFLL) return NSCT_ERR_CLOCK;
    *out_freq = (unsigned int)freq.QuadPart;

    compare = chosen;
    for (i = 0; i < samples; i++)
    {
        QueryPerformanceCounter(&start);
        sink = compare(a, b, n);
        QueryPerformanceCounter(&stop);
        out_ticks[i] = (unsigned int)(stop.QuadPart - start.QuadPart);
    }
    (void)sink;
    return NSCT_OK;
}
