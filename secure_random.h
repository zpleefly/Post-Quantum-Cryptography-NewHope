#ifndef __RANDOM_H__
#define __RANDOM_H__

#include "types.h"

void seed_secure_rand(u32 seed);

u32 secure_rand();

#endif
