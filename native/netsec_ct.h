/*
 * netsec_ct: a leaky compare and a constant-time compare, with a sampler that times each one (lesson 11).
 * Built to show the parts. Do not copy.
 *
 * This file and netsec_ct.c stay plain C, so a CE compiler can take them later. The DLL builds as C++, and
 * native/build.cmd also compiles the same source as C to prove it. Nothing here throws, so nothing can
 * unwind across the boundary.
 *
 * A compare returns 0 when the buffers are equal and a nonzero value otherwise, as memcmp does.
 * Accuracy: the constant-time result was measured only for this source, this compiler, these flags and this CPU. It depends on the optimizer.
 */
#ifndef NETSEC_CT_H
#define NETSEC_CT_H

#ifdef NSCT_BUILD
#define NSCT_API __declspec(dllexport)
#else
#define NSCT_API __declspec(dllimport)
#endif

/* __stdcall on x86, ignored on x64 and ARM. This matches the DllImport default. */
#if defined(_M_IX86)
#define NSCT_CALL __stdcall
#else
#define NSCT_CALL
#endif

#define NSCT_ABI_VERSION 1u

/* The values of "which" in nsct_sample. */
#define NSCT_WHICH_LEAKY 0
#define NSCT_WHICH_CONSTANT_TIME 1

/* The return codes. A compare returns NSCT_ERR_ARGUMENT for a null buffer, which also reads as "not equal". */
#define NSCT_OK 0
#define NSCT_ERR_ARGUMENT (-1)
#define NSCT_ERR_WHICH (-2)
#define NSCT_ERR_CLOCK (-3)

#ifdef __cplusplus
extern "C" {
#endif

NSCT_API unsigned int NSCT_CALL nsct_abi_version(void);

/* Stops at the first byte that differs, so the time tells the caller how many bytes matched. */
NSCT_API int NSCT_CALL nsct_compare_leaky(const unsigned char *a, const unsigned char *b, unsigned int n);

/* Reads every byte, with no branch on secret data. */
NSCT_API int NSCT_CALL nsct_compare_ct(const unsigned char *a, const unsigned char *b, unsigned int n);

/*
 * Runs one compare "samples" times, and writes the ticks of each run to out_ticks. The clock reads sit inside
 * native code, so P/Invoke cost stays out of each sample. out_freq receives the ticks per second.
 * Returns NSCT_OK, NSCT_ERR_ARGUMENT, NSCT_ERR_WHICH or NSCT_ERR_CLOCK.
 */
NSCT_API int NSCT_CALL nsct_sample(int which, const unsigned char *a, const unsigned char *b, unsigned int n,
                                   unsigned int *out_ticks, unsigned int samples, unsigned int *out_freq);

#ifdef __cplusplus
}
#endif

#endif
