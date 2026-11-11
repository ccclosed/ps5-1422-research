#include <stdio.h>
#include <immintrin.h>
int main(void){
    __m256i a = _mm256_setr_epi32(1,2,3,4,5,6,7,8);
    __m256i b = _mm256_setr_epi32(10,20,30,40,50,60,70,80);
    __m256i c = _mm256_add_epi32(a,b);
    volatile int out[8]; _mm256_storeu_si256((__m256i*)out, c);
    long s=0; for(int i=0;i<8;i++) s+=out[i];
    __m256d x=_mm256_set1_pd(1.5), y=_mm256_set1_pd(2.0);
    __m256d z=_mm256_add_pd(x,y); double d[4]; _mm256_storeu_pd(d,z);
    printf("sum=%ld d0=%f\n", s, d[0]);
    return 0;
}
