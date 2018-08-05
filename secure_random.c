#include "secure_random.h"

static u32 state = 0;

void seed_secure_rand(u32 seed)
{
    state = seed;
}

u32 secure_rand()
{
    // This is a REALLY bad PRNG, it is not secure at all!
    // Don't use such a PRNG in actual cryptographic applications.
    return (state = state * 1103515245 + 12345);
}
