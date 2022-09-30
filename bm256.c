/* ========================================================================== */
/*                                                                            */
/*   Filename.c                                                               */
/*   (c) 2012 Author                                                          */
/*                                                                            */
/*   Description                                                              */
/*                                                                            */
/* ========================================================================== */

#include <stdio.h>
#include <string.h>
#include <bm256.h>

unsigned short bm_mult64(unsigned long long a, unsigned long long b, unsigned long long *pprinc, unsigned long long *poverflow){

    unsigned long long overflow = 0, princ = 0, state = 0;
    unsigned long long a1 = a >> 32, a2 = a & 0xffffffff,
                    b1 = b >> 32, b2 = b & 0xffffffff;

    state = a2*b2;
    overflow = state >> 32;
    princ = state & 0xffffffff;

    state = a1*b2 + overflow;
    overflow = state >> 32;
    princ |= state << 32;

    state = a2*b1;
    overflow += state >> 32;
    state &= 0xffffffff;
    state += princ >> 32;

    princ = (state << 32) | (princ & 0xffffffff);
    overflow += (state >> 32) + a1*b1;

    *pprinc = princ;
    *poverflow = overflow;

    return 0;
}

unsigned short bm_add64(unsigned long long a, unsigned long long b, unsigned long long *presult, unsigned long long *poverflow){

    unsigned long long a1 = a >> 32, a2 = a & 0xffffffff, b1 = b >> 32, b2 = b & 0xffffffff, state, overflow, princ;

    state = a2+b2;
    overflow = state >> 32;
    princ = state & 0xffffffff;

    state = a1+b1+overflow;
    overflow = state >> 32;
    princ |= state << 32;

    *presult = princ;
    *poverflow = overflow;
    return 0;
}

unsigned short bm_mult256(const unsigned long long a[4], const unsigned long long b[4], unsigned long long result[4], unsigned long long overflow[4]){

    unsigned long long m[4][5], state1, state2;


    bm_mult64(a[3], b[3], &m[0][4], &m[0][3]);
    bm_mult64(a[2], b[3], &state1, &m[0][2]);
    bm_add64(m[0][3], state1, &m[0][3], &state1);
    bm_add64(m[0][2], state1, &m[0][2], &state1);


    bm_mult64(a[1], b[3], &state1, &m[0][1]);
    bm_add64(m[0][2], state1, &m[0][2], &state1);
    bm_add64(m[0][1], state1, &m[0][1], &state1);

    bm_mult64(a[0], b[3], &state1, &m[0][0]);
    bm_add64(m[0][1], state1, &m[0][1], &state1);
    bm_add64(m[0][0], state1, &m[0][0], &state1);


    bm_mult64(a[3], b[2], &m[1][4], &m[1][3]);
    bm_mult64(a[2], b[2], &state1, &m[1][2]);
    bm_add64(m[1][3], state1, &m[1][3], &state1);
    bm_add64(m[1][2], state1, &m[1][2], &state1);

    bm_mult64(a[1], b[2], &state1, &m[1][1]);
    bm_add64(m[1][2], state1, &m[1][2], &state1);
    bm_add64(m[1][1], state1, &m[1][1], &state1);

    bm_mult64(a[0], b[2], &state1, &m[1][0]);
    bm_add64(m[1][1], state1, &m[1][1], &state1);
    bm_add64(m[1][0], state1, &m[1][0], &state1);


    bm_mult64(a[3], b[1], &m[2][4], &m[2][3]);
    bm_mult64(a[2], b[1], &state1, &m[2][2]);
    bm_add64(m[2][3], state1, &m[2][3], &state1);
    bm_add64(m[2][2], state1, &m[2][2], &state1);

    bm_mult64(a[1], b[1], &state1, &m[2][1]);
    bm_add64(m[2][2], state1, &m[2][2], &state1);
    bm_add64(m[2][1], state1, &m[2][1], &state1);

    bm_mult64(a[0], b[1], &state1, &m[2][0]);
    bm_add64(m[2][1], state1, &m[2][1], &state1);
    bm_add64(m[2][0], state1, &m[2][0], &state1);


    bm_mult64(a[3], b[0], &m[3][4], &m[3][3]);
    bm_mult64(a[2], b[0], &state1, &m[3][2]);
    bm_add64(m[3][3], state1, &m[3][3], &state1);
    bm_add64(m[3][2], state1, &m[3][2], &state1);

    bm_mult64(a[1], b[0], &state1, &m[3][1]);
    bm_add64(m[3][2], state1, &m[3][2], &state1);
    bm_add64(m[3][1], state1, &m[3][1], &state1);

    bm_mult64(a[0], b[0], &state1, &m[3][0]);
    bm_add64(m[3][1], state1, &m[3][1], &state1);
    bm_add64(m[3][0], state1, &m[3][0], &state1);


    bm_add64(m[0][3], m[1][4], &m[0][3], &state1);

    state2 = 0;
    bm_add64(m[0][2], state1, &m[0][2], &state1);
    state2 += state1;
    bm_add64(m[0][2], m[1][3], &m[0][2], &state1);
    state2 += state1;
    bm_add64(m[0][2], m[2][4], &m[0][2], &state1);
    state2 += state1;

    state1 = state2;
    state2 = 0;

    bm_add64(m[0][1], state1, &m[0][1], &state1);
    state2 += state1;
    bm_add64(m[0][1], m[1][2], &m[0][1], &state1);
    state2 += state1;
    bm_add64(m[0][1], m[2][3], &m[0][1], &state1);
    state2 += state1;
    bm_add64(m[0][1], m[3][4], &m[0][1], &state1);
    state2 += state1;

    state1 = state2;
    state2 = 0;

    bm_add64(m[0][0], state1, &m[0][0], &state1);
    state2 += state1;
    bm_add64(m[0][0], m[1][1], &m[0][0], &state1);
    state2 += state1;
    bm_add64(m[0][0], m[2][2], &m[0][0], &state1);
    state2 += state1;
    bm_add64(m[0][0], m[3][3], &m[0][0], &state1);
    state2 += state1;

    state1 = state2;
    state2 = 0;

    bm_add64(m[1][0], state1, &m[1][0], &state1);
    state2 += state1;
    bm_add64(m[1][0], m[2][1], &m[1][0], &state1);
    state2 += state1;
    bm_add64(m[1][0], m[3][2], &m[1][0], &state1);
    state2 += state1;

    state1 = state2;
    state2 = 0;

    bm_add64(m[2][0], state1, &m[2][0], &state1);
    state2 += state1;
    bm_add64(m[2][0], m[3][1], &m[2][0], &state1);
    state2 += state1;

    state1 = state2;
    state2 = 0;
    bm_add64(m[3][0], state1, &m[3][0], &state1);

    overflow[0] = m[3][0];
    overflow[1] = m[2][0];
    overflow[2] = m[1][0];
    overflow[3] = m[0][0];


    result[0] = m[0][1];
    result[1] = m[0][2];
    result[2] = m[0][3];
    result[3] = m[0][4];

    return 0;
}

unsigned short bm_add256(const unsigned long long a[4], const unsigned long long b[4], unsigned long long result[4], unsigned long long *overflow){

    unsigned long long state1 = 0, state2 = 0, r[4] = {0, 0, 0, 0}, oa[4] = {a[0], a[1], a[2], a[3]}, ob[4] = {b[0], b[1], b[2], b[3]};
    bm_add64(oa[3], ob[3], &r[3], &state1);

    bm_add64(oa[2], state1, &r[2], &state1);
    state2 += state1;
    bm_add64(r[2], ob[2], &r[2], &state1);
    state1 = state2 + state1;
    state2 = 0;

    bm_add64(oa[1], state1, &r[1], &state1);
    state2 += state1;
    bm_add64(r[1], ob[1], &r[1], &state1);
    state1 = state2 + state1;
    state2 = 0;

    bm_add64(oa[0], state1, &r[0], &state1);
    state2 += state1;
    bm_add64(r[0], ob[0], &r[0], &state1);
    state1 = state2 + state1;
    state2 = 0;

    *overflow = state1;

    result[0] = r[0];
    result[1] = r[1];
    result[2] = r[2];
    result[3] = r[3];

    return 0;
}

unsigned short bm_emaior256(const unsigned long long a[4], const unsigned long long b[4]){

    unsigned short ret = 0;
    for(int i = 0; i < 4; i++){

        ret += 2*(a[i] > b[i])*(ret == 0);
        ret += (a[i] < b[i])*(ret == 0);
    }

    return ret;
}

unsigned short bm_subtr256(const unsigned long long a[4], const unsigned long long b[4], unsigned long long r[4]){

    unsigned long long ta[4] = {a[0], a[1], a[2], a[3]}, tb[4] = {b[0], b[1], b[2], b[3]};

    r[3] = ta[3] - b[3];
    ta[2] -= b[3] > ta[3];

    r[2] = ta[2] - b[2];
    ta[1] -= b[2] > ta[2];

    r[1] = ta[1] - b[1];
    ta[0] -= b[1] > ta[1];

    r[0] = ta[0] - b[0];

    return 0;
}