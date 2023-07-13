#ifndef PQ_H
#define PQ_H
#include <sys/time.h>

void TLS(int sock, char *opt, int opt2, int flag);
void mfiles (char *filename, unsigned long long dilithium, unsigned long long newhope, unsigned long long aes, unsigned long long total);

#if defined(__i386__)

static __inline__ unsigned long long rdtsc(void) {
  unsigned long long int x;
     __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
     return x;
}

#elif defined(__x86_64__)

static __inline__ unsigned long long rdtsc(void) {
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    unsigned aux = 32;
    return ((unsigned long long) lo) | (((unsigned long long) hi) << aux);
}

#elif defined(__powerpc__)

static __inline__ unsigned long long rdtsc(void) {
  unsigned long long int result=0;
  unsigned long int upper, lower,tmp;
  __asm__ volatile(
                "0:                  \n"
                "\tmftbu   %0           \n"
                "\tmftb    %1           \n"
                "\tmftbu   %2           \n"
                "\tcmpw    %2,%0        \n"
                "\tbne     0b         \n"
                : "=r"(upper),"=r"(lower),"=r"(tmp)
                );
  result = upper;

  unsigned aux = 32;
  result = result<<aux;
  result = result|lower;

  return(result);
}

#elif defined(__ARM_ARCH)

static __inline__ unsigned long long rdtsc(void) {
  // V6 is the earliest arch that has a standard cyclecount
  // Native Client validator doesn't allow MRC instructions.
#if (__ARM_ARCH >= 6)
      unsigned long long pmccntr;
      unsigned long long pmuseren;
      unsigned long long pmcntenset;
      // Read the user mode perf monitor counter access permissions.
      asm volatile("mrc p15, 0, %0, c9, c14, 0" : "=r"(pmuseren));
      if (pmuseren & 1) {  // Allows reading perfmon counters for user mode code.
          asm volatile("mrc p15, 0, %0, c9, c12, 1" : "=r"(pmcntenset));
          if (pmcntenset & 0x80000000ul) {  // Is it counting?
              asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(pmccntr));
              // The counter is set up to count every 64th cycle
              return (pmccntr) * 64;  // Should optimize to << 6
          }
      }

#endif
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (tv.tv_sec) * 1000000 + tv.tv_usec;
}

#endif
#endif
