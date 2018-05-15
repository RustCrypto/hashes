/* 
 * MD5 hash in x86 assembly
 * 
 * Copyright (c) 2016 Project Nayuki. (MIT License)
 * https://www.nayuki.io/page/fast-md5-hash-implementation-in-x86-assembly
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * - The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * - The Software is provided "as is", without warranty of any kind, express or
 *   implied, including but not limited to the warranties of merchantability,
 *   fitness for a particular purpose and noninfringement. In no event shall the
 *   authors or copyright holders be liable for any claim, damages or other
 *   liability, whether in an action of contract, tort or otherwise, arising from,
 *   out of or in connection with the Software or the use or other dealings in the
 *   Software.
 */


/* void md5_compress(uint32_t state[4], const uint8_t block[64]) */
#ifdef __APPLE__
.globl _md5_compress
_md5_compress:
#else
.globl md5_compress
md5_compress:
#endif
    /* 
     * Storage usage:
     *   Bytes  Location  Description
     *       4  eax       MD5 state variable A
     *       4  ebx       MD5 state variable B
     *       4  ecx       MD5 state variable C
     *       4  edx       MD5 state variable D
     *       4  esi       Temporary for calculation per round
     *       4  edi       Temporary for calculation per round
     *       4  ebp       Base address of block array argument (read-only)
     *       4  esp       x86 stack pointer
     *       4  [esp+ 0]  Caller's value of ebx
     *       4  [esp+ 4]  Caller's value of esi
     *       4  [esp+ 8]  Caller's value of edi
     *       4  [esp+12]  Caller's value of ebp
     */
    
    #define ROUND0(a, b, c, d, k, s, t)  \
        movl  %c, %esi;         \
        addl  (k*4)(%ebp), %a;  \
        xorl  %d, %esi;         \
        andl  %b, %esi;         \
        xorl  %d, %esi;         \
        leal  t(%esi,%a), %a;   \
        roll  $s, %a;           \
        addl  %b, %a;
    
    #define ROUND1(a, b, c, d, k, s, t)  \
        movl  %d, %esi;         \
        movl  %d, %edi;         \
        addl  (k*4)(%ebp), %a;  \
        notl  %esi;             \
        andl  %b, %edi;         \
        andl  %c, %esi;         \
        orl   %edi, %esi;       \
        leal  t(%esi,%a), %a;   \
        roll  $s, %a;           \
        addl  %b, %a;
    
    #define ROUND2(a, b, c, d, k, s, t)  \
        movl  %c, %esi;         \
        addl  (k*4)(%ebp), %a;  \
        xorl  %d, %esi;         \
        xorl  %b, %esi;         \
        leal  t(%esi,%a), %a;   \
        roll  $s, %a;           \
        addl  %b, %a;
    
    #define ROUND3(a, b, c, d, k, s, t)  \
        movl  %d, %esi;         \
        not   %esi;             \
        addl  (k*4)(%ebp), %a;  \
        orl   %b, %esi;         \
        xorl  %c, %esi;         \
        leal  t(%esi,%a), %a;   \
        roll  $s, %a;           \
        addl  %b, %a;
    
    /* Save registers */
    subl  $16, %esp
    movl  %ebx,  0(%esp)
    movl  %esi,  4(%esp)
    movl  %edi,  8(%esp)
    movl  %ebp, 12(%esp)
    
    /* Load arguments */
    movl  20(%esp), %esi  /* state */
    movl  24(%esp), %ebp  /* block */
    movl   0(%esi), %eax  /* a */
    movl   4(%esi), %ebx  /* b */
    movl   8(%esi), %ecx  /* c */
    movl  12(%esi), %edx  /* d */
    
    /* 64 rounds of hashing */
    ROUND0(eax, ebx, ecx, edx,  0,  7, 0xD76AA478)
    ROUND0(edx, eax, ebx, ecx,  1, 12, 0xE8C7B756)
    ROUND0(ecx, edx, eax, ebx,  2, 17, 0x242070DB)
    ROUND0(ebx, ecx, edx, eax,  3, 22, 0xC1BDCEEE)
    ROUND0(eax, ebx, ecx, edx,  4,  7, 0xF57C0FAF)
    ROUND0(edx, eax, ebx, ecx,  5, 12, 0x4787C62A)
    ROUND0(ecx, edx, eax, ebx,  6, 17, 0xA8304613)
    ROUND0(ebx, ecx, edx, eax,  7, 22, 0xFD469501)
    ROUND0(eax, ebx, ecx, edx,  8,  7, 0x698098D8)
    ROUND0(edx, eax, ebx, ecx,  9, 12, 0x8B44F7AF)
    ROUND0(ecx, edx, eax, ebx, 10, 17, 0xFFFF5BB1)
    ROUND0(ebx, ecx, edx, eax, 11, 22, 0x895CD7BE)
    ROUND0(eax, ebx, ecx, edx, 12,  7, 0x6B901122)
    ROUND0(edx, eax, ebx, ecx, 13, 12, 0xFD987193)
    ROUND0(ecx, edx, eax, ebx, 14, 17, 0xA679438E)
    ROUND0(ebx, ecx, edx, eax, 15, 22, 0x49B40821)
    ROUND1(eax, ebx, ecx, edx,  1,  5, 0xF61E2562)
    ROUND1(edx, eax, ebx, ecx,  6,  9, 0xC040B340)
    ROUND1(ecx, edx, eax, ebx, 11, 14, 0x265E5A51)
    ROUND1(ebx, ecx, edx, eax,  0, 20, 0xE9B6C7AA)
    ROUND1(eax, ebx, ecx, edx,  5,  5, 0xD62F105D)
    ROUND1(edx, eax, ebx, ecx, 10,  9, 0x02441453)
    ROUND1(ecx, edx, eax, ebx, 15, 14, 0xD8A1E681)
    ROUND1(ebx, ecx, edx, eax,  4, 20, 0xE7D3FBC8)
    ROUND1(eax, ebx, ecx, edx,  9,  5, 0x21E1CDE6)
    ROUND1(edx, eax, ebx, ecx, 14,  9, 0xC33707D6)
    ROUND1(ecx, edx, eax, ebx,  3, 14, 0xF4D50D87)
    ROUND1(ebx, ecx, edx, eax,  8, 20, 0x455A14ED)
    ROUND1(eax, ebx, ecx, edx, 13,  5, 0xA9E3E905)
    ROUND1(edx, eax, ebx, ecx,  2,  9, 0xFCEFA3F8)
    ROUND1(ecx, edx, eax, ebx,  7, 14, 0x676F02D9)
    ROUND1(ebx, ecx, edx, eax, 12, 20, 0x8D2A4C8A)
    ROUND2(eax, ebx, ecx, edx,  5,  4, 0xFFFA3942)
    ROUND2(edx, eax, ebx, ecx,  8, 11, 0x8771F681)
    ROUND2(ecx, edx, eax, ebx, 11, 16, 0x6D9D6122)
    ROUND2(ebx, ecx, edx, eax, 14, 23, 0xFDE5380C)
    ROUND2(eax, ebx, ecx, edx,  1,  4, 0xA4BEEA44)
    ROUND2(edx, eax, ebx, ecx,  4, 11, 0x4BDECFA9)
    ROUND2(ecx, edx, eax, ebx,  7, 16, 0xF6BB4B60)
    ROUND2(ebx, ecx, edx, eax, 10, 23, 0xBEBFBC70)
    ROUND2(eax, ebx, ecx, edx, 13,  4, 0x289B7EC6)
    ROUND2(edx, eax, ebx, ecx,  0, 11, 0xEAA127FA)
    ROUND2(ecx, edx, eax, ebx,  3, 16, 0xD4EF3085)
    ROUND2(ebx, ecx, edx, eax,  6, 23, 0x04881D05)
    ROUND2(eax, ebx, ecx, edx,  9,  4, 0xD9D4D039)
    ROUND2(edx, eax, ebx, ecx, 12, 11, 0xE6DB99E5)
    ROUND2(ecx, edx, eax, ebx, 15, 16, 0x1FA27CF8)
    ROUND2(ebx, ecx, edx, eax,  2, 23, 0xC4AC5665)
    ROUND3(eax, ebx, ecx, edx,  0,  6, 0xF4292244)
    ROUND3(edx, eax, ebx, ecx,  7, 10, 0x432AFF97)
    ROUND3(ecx, edx, eax, ebx, 14, 15, 0xAB9423A7)
    ROUND3(ebx, ecx, edx, eax,  5, 21, 0xFC93A039)
    ROUND3(eax, ebx, ecx, edx, 12,  6, 0x655B59C3)
    ROUND3(edx, eax, ebx, ecx,  3, 10, 0x8F0CCC92)
    ROUND3(ecx, edx, eax, ebx, 10, 15, 0xFFEFF47D)
    ROUND3(ebx, ecx, edx, eax,  1, 21, 0x85845DD1)
    ROUND3(eax, ebx, ecx, edx,  8,  6, 0x6FA87E4F)
    ROUND3(edx, eax, ebx, ecx, 15, 10, 0xFE2CE6E0)
    ROUND3(ecx, edx, eax, ebx,  6, 15, 0xA3014314)
    ROUND3(ebx, ecx, edx, eax, 13, 21, 0x4E0811A1)
    ROUND3(eax, ebx, ecx, edx,  4,  6, 0xF7537E82)
    ROUND3(edx, eax, ebx, ecx, 11, 10, 0xBD3AF235)
    ROUND3(ecx, edx, eax, ebx,  2, 15, 0x2AD7D2BB)
    ROUND3(ebx, ecx, edx, eax,  9, 21, 0xEB86D391)
    
    /* Save updated state */
    movl  20(%esp), %esi
    addl  %eax,  0(%esi)
    addl  %ebx,  4(%esi)
    addl  %ecx,  8(%esi)
    addl  %edx, 12(%esi)
    
    /* Restore registers */
    movl   0(%esp), %ebx
    movl   4(%esp), %esi
    movl   8(%esp), %edi
    movl  12(%esp), %ebp
    addl  $16, %esp
    retl
