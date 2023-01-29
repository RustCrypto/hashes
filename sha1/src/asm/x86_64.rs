// /*
//  * SHA-1 hash in x86-64 assembly
//  *
//  * Copyright (c) 2015 Project Nayuki. (MIT License)
//  * https://www.nayuki.io/page/fast-sha1-hash-implementation-in-x86-assembly
//  *
//  * Permission is hereby granted, free of charge, to any person obtaining a copy of
//  * this software and associated documentation files (the "Software"), to deal in
//  * the Software without restriction, including without limitation the rights to
//  * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
//  * the Software, and to permit persons to whom the Software is furnished to do so,
//  * subject to the following conditions:
//  * - The above copyright notice and this permission notice shall be included in
//  *   all copies or substantial portions of the Software.
//  * - The Software is provided "as is", without warranty of any kind, express or
//  *   implied, including but not limited to the warranties of merchantability,
//  *   fitness for a particular purpose and noninfringement. In no event shall the
//  *   authors or copyright holders be liable for any claim, damages or other
//  *   liability, whether in an action of contract, tort or otherwise, arising from,
//  *   out of or in connection with the Software or the use or other dealings in the
//  *   Software.
//  */
//
//
// /* void sha1_compress(uint32_t state[5], const uint8_t block[64]) */
// #ifdef __APPLE__
// .globl _sha1_compress
// _sha1_compress:
// #else
// .globl sha1_compress
// sha1_compress:
// #endif
//     /*
//      * Storage usage:
//      *   Bytes  Location  Description
//      *       4  eax       SHA-1 state variable A
//      *       4  ebx       SHA-1 state variable B
//      *       4  ecx       SHA-1 state variable C
//      *       4  edx       SHA-1 state variable D
//      *       4  ebp       SHA-1 state variable E
//      *       4  esi       Temporary for calculation per round
//      *       4  edi       (Last 64 rounds) temporary for calculation per round
//      *       8  rdi       (First 16 rounds) base address of block array argument (read-only)
//      *       8  r8        Base address of state array argument (read-only)
//      *       8  rsp       x86-64 stack pointer
//      *      64  [rsp+0]   Circular buffer of most recent 16 key schedule items, 4 bytes each
//      *      16  xmm0      Caller's value of rbx (only low 64 bits are used)
//      *      16  xmm1      Caller's value of rbp (only low 64 bits are used)
//      */
//
//     #define round0a(a, b, c, d, e, i)  \
//         movl    (i*4)(%rdi), %esi;  \
//         bswapl  %esi;               \
//         movl    %esi, (i*4)(%rsp);  \
//         addl    %esi, %e;           \
//         movl    %c, %esi;           \
//         xorl    %d, %esi;           \
//         andl    %b, %esi;           \
//         xorl    %d, %esi;           \
//         ROUNDTAIL(a, b, e, i, 0x5A827999)
//
//     #define SCHEDULE(i, e)  \
//         movl  (((i- 3)&0xF)*4)(%rsp), %esi;  \
//         xorl  (((i- 8)&0xF)*4)(%rsp), %esi;  \
//         xorl  (((i-14)&0xF)*4)(%rsp), %esi;  \
//         xorl  (((i-16)&0xF)*4)(%rsp), %esi;  \
//         roll  $1, %esi;                      \
//         addl  %esi, %e;                      \
//         movl  %esi, ((i&0xF)*4)(%rsp);
//
//     #define ROUND0b(a, b, c, d, e, i)  \
//         SCHEDULE(i, e)   \
//         movl  %c, %esi;  \
//         xorl  %d, %esi;  \
//         andl  %b, %esi;  \
//         xorl  %d, %esi;  \
//         ROUNDTAIL(a, b, e, i, 0x5A827999)
//
//     #define ROUND1(a, b, c, d, e, i)  \
//         SCHEDULE(i, e)   \
//         movl  %b, %esi;  \
//         xorl  %c, %esi;  \
//         xorl  %d, %esi;  \
//         ROUNDTAIL(a, b, e, i, 0x6ED9EBA1)
//
//     #define ROUND2(a, b, c, d, e, i)  \
//         SCHEDULE(i, e)     \
//         movl  %c, %esi;    \
//         movl  %c, %edi;    \
//         orl   %d, %esi;    \
//         andl  %b, %esi;    \
//         andl  %d, %edi;    \
//         orl   %edi, %esi;  \
//         ROUNDTAIL(a, b, e, i, -0x70E44324)
//
//     #define ROUND3(a, b, c, d, e, i)  \
//         SCHEDULE(i, e)   \
//         movl  %b, %esi;  \
//         xorl  %c, %esi;  \
//         xorl  %d, %esi;  \
//         ROUNDTAIL(a, b, e, i, -0x359D3E2A)
//
//     #define ROUNDTAIL(a, b, e, i, k)  \
//         roll  $30, %b;         \
//         leal  k(%e,%esi), %e;  \
//         movl  %a, %esi;        \
//         roll  $5, %esi;        \
//         addl  %esi, %e;
//
//     /* Save registers, allocate scratch space */
//     movq    %rbx, %xmm0
//     movq    %rbp, %xmm1
//     subq    $64, %rsp
//
//     /* Load arguments */
//     movq    %rdi, %r8
//     movl     0(%rdi), %eax  /* a */
//     movl     4(%rdi), %ebx  /* b */
//     movl     8(%rdi), %ecx  /* c */
//     movl    12(%rdi), %edx  /* d */
//     movl    16(%rdi), %ebp  /* e */
//     movq    %rsi, %rdi
//
//     /* 80 rounds of hashing */
//     round0a(eax, ebx, ecx, edx, ebp,  0)
//     round0a(ebp, eax, ebx, ecx, edx,  1)
//     round0a(edx, ebp, eax, ebx, ecx,  2)
//     round0a(ecx, edx, ebp, eax, ebx,  3)
//     round0a(ebx, ecx, edx, ebp, eax,  4)
//     round0a(eax, ebx, ecx, edx, ebp,  5)
//     round0a(ebp, eax, ebx, ecx, edx,  6)
//     round0a(edx, ebp, eax, ebx, ecx,  7)
//     round0a(ecx, edx, ebp, eax, ebx,  8)
//     round0a(ebx, ecx, edx, ebp, eax,  9)
//     round0a(eax, ebx, ecx, edx, ebp, 10)
//     round0a(ebp, eax, ebx, ecx, edx, 11)
//     round0a(edx, ebp, eax, ebx, ecx, 12)
//     round0a(ecx, edx, ebp, eax, ebx, 13)
//     round0a(ebx, ecx, edx, ebp, eax, 14)
//     round0a(eax, ebx, ecx, edx, ebp, 15)
//     ROUND0b(ebp, eax, ebx, ecx, edx, 16)
//     ROUND0b(edx, ebp, eax, ebx, ecx, 17)
//     ROUND0b(ecx, edx, ebp, eax, ebx, 18)
//     ROUND0b(ebx, ecx, edx, ebp, eax, 19)
//     ROUND1(eax, ebx, ecx, edx, ebp, 20)
//     ROUND1(ebp, eax, ebx, ecx, edx, 21)
//     ROUND1(edx, ebp, eax, ebx, ecx, 22)
//     ROUND1(ecx, edx, ebp, eax, ebx, 23)
//     ROUND1(ebx, ecx, edx, ebp, eax, 24)
//     ROUND1(eax, ebx, ecx, edx, ebp, 25)
//     ROUND1(ebp, eax, ebx, ecx, edx, 26)
//     ROUND1(edx, ebp, eax, ebx, ecx, 27)
//     ROUND1(ecx, edx, ebp, eax, ebx, 28)
//     ROUND1(ebx, ecx, edx, ebp, eax, 29)
//     ROUND1(eax, ebx, ecx, edx, ebp, 30)
//     ROUND1(ebp, eax, ebx, ecx, edx, 31)
//     ROUND1(edx, ebp, eax, ebx, ecx, 32)
//     ROUND1(ecx, edx, ebp, eax, ebx, 33)
//     ROUND1(ebx, ecx, edx, ebp, eax, 34)
//     ROUND1(eax, ebx, ecx, edx, ebp, 35)
//     ROUND1(ebp, eax, ebx, ecx, edx, 36)
//     ROUND1(edx, ebp, eax, ebx, ecx, 37)
//     ROUND1(ecx, edx, ebp, eax, ebx, 38)
//     ROUND1(ebx, ecx, edx, ebp, eax, 39)
//     ROUND2(eax, ebx, ecx, edx, ebp, 40)
//     ROUND2(ebp, eax, ebx, ecx, edx, 41)
//     ROUND2(edx, ebp, eax, ebx, ecx, 42)
//     ROUND2(ecx, edx, ebp, eax, ebx, 43)
//     ROUND2(ebx, ecx, edx, ebp, eax, 44)
//     ROUND2(eax, ebx, ecx, edx, ebp, 45)
//     ROUND2(ebp, eax, ebx, ecx, edx, 46)
//     ROUND2(edx, ebp, eax, ebx, ecx, 47)
//     ROUND2(ecx, edx, ebp, eax, ebx, 48)
//     ROUND2(ebx, ecx, edx, ebp, eax, 49)
//     ROUND2(eax, ebx, ecx, edx, ebp, 50)
//     ROUND2(ebp, eax, ebx, ecx, edx, 51)
//     ROUND2(edx, ebp, eax, ebx, ecx, 52)
//     ROUND2(ecx, edx, ebp, eax, ebx, 53)
//     ROUND2(ebx, ecx, edx, ebp, eax, 54)
//     ROUND2(eax, ebx, ecx, edx, ebp, 55)
//     ROUND2(ebp, eax, ebx, ecx, edx, 56)
//     ROUND2(edx, ebp, eax, ebx, ecx, 57)
//     ROUND2(ecx, edx, ebp, eax, ebx, 58)
//     ROUND2(ebx, ecx, edx, ebp, eax, 59)
//     ROUND3(eax, ebx, ecx, edx, ebp, 60)
//     ROUND3(ebp, eax, ebx, ecx, edx, 61)
//     ROUND3(edx, ebp, eax, ebx, ecx, 62)
//     ROUND3(ecx, edx, ebp, eax, ebx, 63)
//     ROUND3(ebx, ecx, edx, ebp, eax, 64)
//     ROUND3(eax, ebx, ecx, edx, ebp, 65)
//     ROUND3(ebp, eax, ebx, ecx, edx, 66)
//     ROUND3(edx, ebp, eax, ebx, ecx, 67)
//     ROUND3(ecx, edx, ebp, eax, ebx, 68)
//     ROUND3(ebx, ecx, edx, ebp, eax, 69)
//     ROUND3(eax, ebx, ecx, edx, ebp, 70)
//     ROUND3(ebp, eax, ebx, ecx, edx, 71)
//     ROUND3(edx, ebp, eax, ebx, ecx, 72)
//     ROUND3(ecx, edx, ebp, eax, ebx, 73)
//     ROUND3(ebx, ecx, edx, ebp, eax, 74)
//     ROUND3(eax, ebx, ecx, edx, ebp, 75)
//     ROUND3(ebp, eax, ebx, ecx, edx, 76)
//     ROUND3(edx, ebp, eax, ebx, ecx, 77)
//     ROUND3(ecx, edx, ebp, eax, ebx, 78)
//     ROUND3(ebx, ecx, edx, ebp, eax, 79)
//
//     /* Save updated state */
//     addl    %eax,  0(%r8)
//     addl    %ebx,  4(%r8)
//     addl    %ecx,  8(%r8)
//     addl    %edx, 12(%r8)
//     addl    %ebp, 16(%r8)
//
//     /* Restore registers */
//     movq    %xmm0, %rbx
//     movq    %xmm1, %rbp
//     addq    $64, %rsp
//     retq
