#ifndef __NTT_OMEGAS_H__
#define __NTT_OMEGAS_H__

#include "types.h"

u16 ntt_psi[NEWHOPE_N] =
{
    0x0001, 0x2a3a, 0x1be7, 0x0fcb, 0x2ae8, 0x02d2, 0x1668, 0x1fdb, 0x0dd6,
    0x2251, 0x2610, 0x0e25, 0x2993, 0x04bc, 0x0c7b, 0x16e4, 0x1d2c, 0x0a4f,
    0x25c0, 0x2c4c, 0x2dce, 0x2462, 0x2443, 0x2549, 0x1660, 0x1e12, 0x139f,
    0x16c4, 0x2301, 0x1970, 0x1c8f, 0x0547, 0x090f, 0x2b6f, 0x2c46, 0x2ceb,
    0x2380, 0x0bc6, 0x13de, 0x2ad3, 0x12ee, 0x2546, 0x23c2, 0x0e80, 0x12c5,
    0x2220, 0x2bdb, 0x270b, 0x0c13, 0x2fb0, 0x1f21, 0x2c19, 0x246e, 0x1ce1,
    0x2416, 0x093e, 0x2b68, 0x1f62, 0x299e, 0x2531, 0x2f75, 0x28c4, 0x1dfe,
    0x2d2b, 0x04ec, 0x1124, 0x1218, 0x1986, 0x097a, 0x014e, 0x0594, 0x06a0,
    0x07dd, 0x2328, 0x02d9, 0x0ca9, 0x0b41, 0x0cd4, 0x1c1d, 0x27d8, 0x2193,
    0x1bc6, 0x2922, 0x2186, 0x0d36, 0x2e9e, 0x260d, 0x1f7a, 0x0e35, 0x0d83,
    0x0091, 0x1a5b, 0x2556, 0x20a5, 0x1ce7, 0x18ea, 0x24e7, 0x01e0, 0x03fe,
    0x0009, 0x265d, 0x0153, 0x169f, 0x0220, 0x2978, 0x10b6, 0x1b2e, 0x1c84,
    0x1fb0, 0x2201, 0x0565, 0x2624, 0x2c48, 0x215d, 0x033b, 0x1687, 0x09ac,
    0x0076, 0x0895, 0x1c36, 0x0f6d, 0x2321, 0x1164, 0x095c, 0x1eff, 0x0082,
    0x0b15, 0x1b03, 0x0961, 0x01ba, 0x1c14, 0x2bd6, 0x0186, 0x0305, 0x2108,
    0x0ec2, 0x0162, 0x12fd, 0x24a1, 0x1642, 0x1394, 0x2650, 0x0b2b, 0x2bec,
    0x03f9, 0x1cec, 0x0660, 0x1c25, 0x001b, 0x2407, 0x214e, 0x2a61, 0x0601,
    0x00f2, 0x126a, 0x1fd2, 0x258b, 0x0e78, 0x139b, 0x2de0, 0x03ea, 0x1393,
    0x13e0, 0x1f45, 0x1c91, 0x29ba, 0x213d, 0x2c96, 0x267c, 0x0e3e, 0x1786,
    0x0bab, 0x25fb, 0x2776, 0x186a, 0x268b, 0x2bd8, 0x085f, 0x2e6d, 0x1ddc,
    0x0490, 0x149d, 0x2b4a, 0x0cb0, 0x01ed, 0x2001, 0x1abd, 0x094d, 0x1f10,
    0x2e4e, 0x0562, 0x0778, 0x0876, 0x0f4b, 0x2f90, 0x1cca, 0x2f61, 0x0c4d,
    0x2ffe, 0x1155, 0x0e34, 0x134a, 0x14ab, 0x0a90, 0x2a6f, 0x1dd3, 0x067f,
    0x2910, 0x0d24, 0x0699, 0x0fd9, 0x233a, 0x24e2, 0x1ec3, 0x087e, 0x1114,
    0x1c4f, 0x2700, 0x0fd5, 0x0a55, 0x144b, 0x2525, 0x1ce2, 0x05cc, 0x2352,
    0x2583, 0x2077, 0x2468, 0x26bf, 0x0b31, 0x14d4, 0x0db6, 0x065e, 0x27b3,
    0x151f, 0x0c72, 0x2b80, 0x24bd, 0x2738, 0x2031, 0x26a2, 0x22b9, 0x1bba,
    0x23c1, 0x2449, 0x029f, 0x0bc8, 0x00f3, 0x1a4a, 0x01a4, 0x277f, 0x0608,
    0x0f91, 0x1329, 0x0dcb, 0x01dc, 0x0031, 0x04ef, 0x171b, 0x05cb, 0x263d,
    0x2a30, 0x29d2, 0x18cb, 0x05e8, 0x015e, 0x28ea, 0x1507, 0x14f9, 0x27f8,
    0x237f, 0x118d, 0x254f, 0x1915, 0x199a, 0x0a5f, 0x2440, 0x069d, 0x00ae,
    0x02d3, 0x284a, 0x2154, 0x015b, 0x0b6d, 0x230e, 0x2e57, 0x0742, 0x1292,
    0x0bd6, 0x1013, 0x0939, 0x28ce, 0x0b5c, 0x00da, 0x0d6a, 0x2238, 0x0f7b,
    0x0240, 0x17fe, 0x2672, 0x07a2, 0x27fe, 0x24bf, 0x28f4, 0x0f97, 0x2080,
    0x2532, 0x009c, 0x08e9, 0x16f4, 0x2812, 0x14d5, 0x0ebc, 0x01a2, 0x1714,
    0x2e3c, 0x1535, 0x1d5b, 0x1d80, 0x050d, 0x0127, 0x17d3, 0x1686, 0x028c,
    0x2051, 0x0fed, 0x214f, 0x249a, 0x0145, 0x2a85, 0x2b87, 0x2c4d, 0x1766,
    0x0487, 0x2171, 0x2030, 0x0d01, 0x10ca, 0x2f59, 0x0a84, 0x1749, 0x1c0f,
    0x2857, 0x063a, 0x1817, 0x2606, 0x1bc1, 0x2b51, 0x0550, 0x0f74, 0x181a,
    0x14b1, 0x2012, 0x2bdf, 0x039a, 0x01b9, 0x07a6, 0x10e2, 0x0458, 0x081e,
    0x0fce, 0x02c5, 0x23b3, 0x0527, 0x1090, 0x220f, 0x1850, 0x2cbe, 0x099b,
    0x02ab, 0x0e48, 0x2fc1, 0x29e3, 0x1696, 0x247d, 0x263a, 0x23ce, 0x292e,
    0x2413, 0x1a93, 0x1eb0, 0x18e2, 0x0efa, 0x1b78, 0x1b88, 0x2499, 0x1fb8,
    0x23ca, 0x1aa5, 0x03f2, 0x2267, 0x0313, 0x13c1, 0x125a, 0x12ac, 0x228c,
    0x2f41, 0x0529, 0x1330, 0x2800, 0x02a5, 0x190f, 0x185a, 0x22f9, 0x052b,
    0x2533, 0x2fcd, 0x0c66, 0x062b, 0x2e52, 0x2638, 0x1712, 0x0f75, 0x24ea,
    0x0097, 0x27b2, 0x2fc7, 0x2f10, 0x0dcc, 0x2c16, 0x07a4, 0x1c70, 0x2c8c,
    0x1889, 0x0d95, 0x19d0, 0x008e, 0x2bb0, 0x24e5, 0x0d6e, 0x2c32, 0x1074,
    0x242c, 0x1a27, 0x12ae, 0x16fe, 0x1f8c, 0x01f8, 0x08fe, 0x2da4, 0x2e5c,
    0x2011, 0x0e12, 0x17b4, 0x21f1, 0x0cbf, 0x17bd, 0x1df1, 0x1e8e, 0x1d4c,
    0x1a60, 0x128d, 0x1161, 0x1ab1, 0x2f6e, 0x2134, 0x17e6, 0x2117, 0x04a6,
    0x2586, 0x0f14, 0x1545, 0x1e49, 0x2be7, 0x13d7, 0x2343, 0x0879, 0x2df7,
    0x1f1d, 0x1334, 0x2016, 0x14c3, 0x2b03, 0x26d9, 0x07b5, 0x1a3b, 0x2247,
    0x2bf0, 0x1725, 0x2c07, 0x028e, 0x0ded, 0x06a6, 0x07c3, 0x1a68, 0x1456,
    0x0c7f, 0x2fc9, 0x17f8, 0x191b, 0x1ada, 0x21c6, 0x1354, 0x1808, 0x0190,
    0x2941, 0x14db, 0x1546, 0x0e7e, 0x17cd, 0x01d4, 0x206d, 0x013c, 0x2e83,
    0x2810, 0x2063, 0x0f27, 0x0782, 0x2ab2, 0x1ac6, 0x03cd, 0x2b1b, 0x0007,
    0x0790, 0x034d, 0x0e8b, 0x0c52, 0x13be, 0x0cd5, 0x1ef9, 0x00d8, 0x0032,
    0x1a6b, 0x0301, 0x02ff, 0x2124, 0x275c, 0x1039, 0x0c30, 0x1828, 0x183b,
    0x160e, 0x209c, 0x0ea9, 0x0dd0, 0x14fa, 0x0c9d, 0x127a, 0x2957, 0x0f59,
    0x0502, 0x220d, 0x07e5, 0x24f1, 0x0f68, 0x1003, 0x15e4, 0x1a67, 0x087b,
    0x2269, 0x2b10, 0x0bbf, 0x2480, 0x14e5, 0x0a49, 0x057e, 0x2361, 0x2edc,
    0x12f7, 0x2148, 0x2484, 0x2dca, 0x19e3, 0x14a9, 0x0efd, 0x0a23, 0x0c95,
    0x10b1, 0x0fd2, 0x1baa, 0x034c, 0x1452, 0x2c2d, 0x2d57, 0x11ee, 0x1c27,
    0x2274, 0x17fa, 0x1ea6, 0x22a7, 0x1255, 0x0922, 0x270c, 0x2e60, 0x070a,
    0x0613, 0x13ef, 0x289e, 0x1ec6, 0x29cb, 0x04c7, 0x26e3, 0x2b01, 0x0266,
    0x2fe9, 0x2aa6, 0x2c79, 0x264c, 0x1a56, 0x1c52, 0x0371, 0x2e94, 0x03f7,
    0x287a, 0x1555, 0x247f, 0x0a4d, 0x1e63, 0x124c, 0x0d20, 0x1bf2, 0x003f,
    0x1c86, 0x0945, 0x0e56, 0x0ee0, 0x0242, 0x14f8, 0x2e3f, 0x0798, 0x1dcc,
    0x2e03, 0x25c3, 0x1af7, 0x15f2, 0x2987, 0x169d, 0x0dae, 0x13b3, 0x033a,
    0x0c12, 0x0576, 0x0bf9, 0x05e2, 0x19ba, 0x1183, 0x18f5, 0x038e, 0x1d92,
    0x2d12, 0x11a6, 0x0c16, 0x0488, 0x12d4, 0x0aaa, 0x1523, 0x2734, 0x074c,
    0x09ae, 0x24e9, 0x1062, 0x0bcb, 0x290a, 0x1c2b, 0x1e2c, 0x136e, 0x1bcf,
    0x0a70, 0x2ca0, 0x04ff, 0x00bd, 0x0c2c, 0x291e, 0x08a1, 0x2a07, 0x069e,
    0x20e4, 0x1eba, 0x16c8, 0x0546, 0x293b, 0x211a, 0x1b66, 0x2903, 0x2b1e,
    0x1adf, 0x07f3, 0x0410, 0x28a7, 0x1814, 0x1d5f, 0x03b0, 0x14a7, 0x21ac,
    0x19d8, 0x2435, 0x1ae3, 0x1dc8, 0x12e2, 0x0a98, 0x24f5, 0x1100, 0x1ff0,
    0x0048, 0x0f00, 0x28cf, 0x0d7b, 0x2003, 0x2b28, 0x111a, 0x196c, 0x241c,
    0x25ae, 0x0447, 0x0b39, 0x0b0b, 0x2cea, 0x0982, 0x2ba1, 0x261a, 0x2fec,
    0x1951, 0x036a, 0x2704, 0x00aa, 0x19ef, 0x0903, 0x10c1, 0x2d79, 0x2f6b,
    0x2bfb, 0x2e2f, 0x0eed, 0x0691, 0x1229, 0x1751, 0x0b71, 0x178a, 0x0625,
    0x20fb, 0x0ed1, 0x1852, 0x2e0b, 0x13fe, 0x0a2a, 0x2894, 0x0739, 0x1690,
    0x233d, 0x0ed3, 0x1f34, 0x1e56, 0x01c9, 0x2ff9, 0x2c92, 0x25e0, 0x03d6,
    0x271d, 0x107a, 0x1126, 0x2283, 0x2153, 0x1e69, 0x030a, 0x0212, 0x0a42,
    0x0dfa, 0x1259, 0x2277, 0x06a5, 0x2803, 0x0b7c, 0x2474, 0x2a38, 0x0cf5,
    0x261d, 0x008b, 0x0d04, 0x0157, 0x2289, 0x11ba, 0x288d, 0x1ba6, 0x074a,
    0x04b8, 0x1d8a, 0x2958, 0x0992, 0x2e61, 0x032e, 0x02cc, 0x27c3, 0x0874,
    0x1ad9, 0x1524, 0x1f90, 0x2333, 0x1898, 0x0dbb, 0x2e4b, 0x04c2, 0x13c5,
    0x2a01, 0x2948, 0x097d, 0x1ffa, 0x055d, 0x245b, 0x02cd, 0x21fc, 0x22d9,
    0x1083, 0x108e, 0x2d9d, 0x1f83, 0x05f6, 0x2de5, 0x2f84, 0x0c5b, 0x0fc0,
    0x17ef, 0x1d19, 0x056d, 0x27ed, 0x1134, 0x2ea7, 0x0d1f, 0x237c, 0x1459,
    0x0444, 0x0e5e, 0x10a9, 0x2879, 0x01d0, 0x0722, 0x0b6e, 0x1189, 0x239e,
    0x0470, 0x0d79, 0x0e7c, 0x235b, 0x0811, 0x16c2, 0x0da7, 0x11d4, 0x2233,
    0x0f79, 0x2925, 0x1031, 0x08e3, 0x099d, 0x10ab, 0x1615, 0x13c7, 0x1fb1,
    0x2a13, 0x214c, 0x2b06, 0x1584, 0x2b69, 0x199b, 0x12fc, 0x0465, 0x2a5c,
    0x2b96, 0x189e, 0x1a25, 0x0243, 0x0f31, 0x2530, 0x0c2a, 0x18b3, 0x00d4,
    0x207a, 0x1313, 0x1936, 0x0c0f, 0x0589, 0x162c, 0x1e68, 0x08d1, 0x0ea0,
    0x1363, 0x09e0, 0x2411, 0x13ee, 0x2e65, 0x1a2d, 0x192c, 0x133c, 0x12ad,
    0x03f6, 0x2e41, 0x052f, 0x0e17, 0x0f66, 0x1b91, 0x0a9d, 0x003c, 0x0c80,
    0x2a02, 0x16cc, 0x1e2b, 0x08d4, 0x0044, 0x00b4, 0x102a, 0x1e04, 0x0a81,
    0x2a80, 0x1b9e, 0x00cc, 0x1585, 0x2a45, 0x2074, 0x22b2, 0x01cf, 0x2ac1,
    0x241f, 0x264e, 0x27fb, 0x1283, 0x1f66, 0x1a73, 0x04ca, 0x242d, 0x1460,
    0x2e95, 0x26c9, 0x2b2d, 0x2438, 0x1b83, 0x117b, 0x0c31, 0x1261, 0x0421,
    0x25d9, 0x2e6b, 0x296a, 0x0092, 0x1494, 0x057b, 0x070c, 0x17ce, 0x1bbc,
    0x2f12, 0x24ad, 0x03e2, 0x11ca, 0x123e, 0x2e01, 0x1558, 0x132a, 0x0d2f,
    0x270e, 0x22c0, 0x10ef, 0x1cd0, 0x0dc8, 0x0ef1, 0x1f76, 0x247e, 0x2073,
    0x027c, 0x15e9, 0x2d93, 0x2938, 0x1628, 0x1193, 0x15de, 0x0d10, 0x289d,
    0x21d9, 0x19a5, 0x2ad4, 0x2bfc, 0x2868, 0x1747, 0x279d, 0x208a, 0x16a5,
    0x098a, 0x04e0, 0x13fb, 0x134b, 0x2adf, 0x06d0, 0x0b4e, 0x21bb, 0x19c7,
    0x266a, 0x2096, 0x0152, 0x0d0f, 0x1fea, 0x05f2, 0x279a, 0x2fed, 0x138a,
    0x1200, 0x142b, 0x11e2, 0x0179, 0x2e8a, 0x0654, 0x28d5, 0x2e58, 0x2778,
    0x2e79, 0x17c5, 0x1fba, 0x2bf3, 0x2c66, 0x274a, 0x1835, 0x0af0, 0x00c1,
    0x01fa, 0x04e7, 0x0570, 0x1698, 0x0ccc, 0x22f7, 0x08a4, 0x258f, 0x286b,
    0x22b1, 0x0a0f, 0x048d, 0x0ad8, 0x2b67, 0x1a9b, 0x0db7
};

u16 ntt_inv_psi[NEWHOPE_N] =
{
    0x0001, 0x05c7, 0x2036, 0x141a, 0x1026, 0x1999, 0x2d2f, 0x0519, 0x191d,
    0x2386, 0x2b45, 0x066e, 0x21dc, 0x09f1, 0x0db0, 0x222b, 0x2aba, 0x1372,
    0x1691, 0x0d00, 0x193d, 0x1c62, 0x11ef, 0x19a1, 0x0ab8, 0x0bbe, 0x0b9f,
    0x0233, 0x03b5, 0x0a41, 0x25b2, 0x12d5, 0x02d6, 0x1203, 0x073d, 0x008c,
    0x0ad0, 0x0663, 0x109f, 0x0499, 0x26c3, 0x0beb, 0x1320, 0x0b93, 0x03e8,
    0x10e0, 0x0051, 0x23ee, 0x08f6, 0x0426, 0x0de1, 0x1d3c, 0x2181, 0x0c3f,
    0x0abb, 0x1d13, 0x052e, 0x1c23, 0x243b, 0x0c81, 0x0316, 0x03bb, 0x0492,
    0x26f2, 0x14fe, 0x24ec, 0x2f7f, 0x1102, 0x26a5, 0x1e9d, 0x0ce0, 0x2094,
    0x13cb, 0x276c, 0x2f8b, 0x2655, 0x197a, 0x2cc6, 0x0ea4, 0x03b9, 0x09dd,
    0x2a9c, 0x0e00, 0x1051, 0x137d, 0x14d3, 0x1f4b, 0x0689, 0x2de1, 0x1962,
    0x2eae, 0x09a4, 0x2ff8, 0x2c03, 0x2e21, 0x0b1a, 0x1717, 0x131a, 0x0f5c,
    0x0aab, 0x15a6, 0x2f70, 0x227e, 0x21cc, 0x1087, 0x09f4, 0x0163, 0x22cb,
    0x0e7b, 0x06df, 0x143b, 0x0e6e, 0x0829, 0x13e4, 0x232d, 0x24c0, 0x2358,
    0x2d28, 0x0cd9, 0x2824, 0x2961, 0x2a6d, 0x2eb3, 0x2687, 0x167b, 0x1de9,
    0x1edd, 0x2b15, 0x2e25, 0x2236, 0x1cd8, 0x2070, 0x29f9, 0x0882, 0x2e5d,
    0x15b7, 0x2f0e, 0x2439, 0x2d62, 0x0bb8, 0x0c40, 0x1447, 0x0d48, 0x095f,
    0x0fd0, 0x08c9, 0x0b44, 0x0481, 0x238f, 0x1ae2, 0x084e, 0x29a3, 0x224b,
    0x1b2d, 0x24d0, 0x0942, 0x0b99, 0x0f8a, 0x0a7e, 0x0caf, 0x2a35, 0x131f,
    0x0adc, 0x1bb6, 0x25ac, 0x202c, 0x0901, 0x13b2, 0x1eed, 0x2783, 0x113e,
    0x0b1f, 0x0cc7, 0x2028, 0x2968, 0x22dd, 0x06f1, 0x2982, 0x122e, 0x0592,
    0x2571, 0x1b56, 0x1cb7, 0x21cd, 0x1eac, 0x0003, 0x23b4, 0x00a0, 0x1337,
    0x0071, 0x20b6, 0x278b, 0x2889, 0x2a9f, 0x01b3, 0x10f1, 0x26b4, 0x1544,
    0x1000, 0x2e14, 0x2351, 0x04b7, 0x1b64, 0x2b71, 0x1225, 0x0194, 0x27a2,
    0x0429, 0x0976, 0x1797, 0x088b, 0x0a06, 0x2456, 0x187b, 0x21c3, 0x0985,
    0x036b, 0x0ec4, 0x0647, 0x1370, 0x10bc, 0x1c21, 0x1c6e, 0x2c17, 0x0221,
    0x1c66, 0x2189, 0x0a76, 0x102f, 0x1d97, 0x2f0f, 0x2a00, 0x05a0, 0x0eb3,
    0x0bfa, 0x2fe6, 0x13dc, 0x29a1, 0x1315, 0x2c08, 0x0415, 0x24d6, 0x09b1,
    0x1c6d, 0x19bf, 0x0b60, 0x1d04, 0x2e9f, 0x213f, 0x0ef9, 0x2cfc, 0x2e7b,
    0x042b, 0x13ed, 0x2e47, 0x26a0, 0x04e6, 0x2c34, 0x153b, 0x054f, 0x287f,
    0x20da, 0x0f9e, 0x07f1, 0x017e, 0x2ec5, 0x0f94, 0x2e2d, 0x1834, 0x2183,
    0x1abb, 0x1b26, 0x06c0, 0x2e71, 0x17f9, 0x1cad, 0x0e3b, 0x1527, 0x16e6,
    0x1809, 0x0038, 0x2382, 0x1bab, 0x1599, 0x283e, 0x295b, 0x2214, 0x2d73,
    0x03fa, 0x18dc, 0x0411, 0x0dba, 0x15c6, 0x284c, 0x0928, 0x04fe, 0x1b3e,
    0x0feb, 0x1ccd, 0x10e4, 0x020a, 0x2788, 0x0cbe, 0x1c2a, 0x041a, 0x11b8,
    0x1abc, 0x20ed, 0x0a7b, 0x2b5b, 0x0eea, 0x181b, 0x0ecd, 0x0093, 0x1550,
    0x1ea0, 0x1d74, 0x15a1, 0x12b5, 0x1173, 0x1210, 0x1844, 0x2342, 0x0e10,
    0x184d, 0x21ef, 0x0ff0, 0x01a5, 0x025d, 0x2703, 0x2e09, 0x1075, 0x1903,
    0x1d53, 0x15da, 0x0bd5, 0x1f8d, 0x03cf, 0x2293, 0x0b1c, 0x0451, 0x2f73,
    0x1631, 0x226c, 0x1778, 0x0375, 0x1391, 0x285d, 0x03eb, 0x2235, 0x00f1,
    0x003a, 0x084f, 0x2f6a, 0x0b17, 0x208c, 0x18ef, 0x09c9, 0x01af, 0x29d6,
    0x239b, 0x0034, 0x0ace, 0x2ad6, 0x0d08, 0x17a7, 0x16f2, 0x2d5c, 0x0801,
    0x1cd1, 0x2ad8, 0x00c0, 0x0d75, 0x1d55, 0x1da7, 0x1c40, 0x2cee, 0x0d9a,
    0x2c0f, 0x155c, 0x0c37, 0x1049, 0x0b68, 0x1479, 0x1489, 0x2107, 0x171f,
    0x1151, 0x156e, 0x0bee, 0x06d3, 0x0c33, 0x09c7, 0x0b84, 0x196b, 0x061e,
    0x0040, 0x21b9, 0x2d56, 0x2666, 0x0343, 0x17b1, 0x0df2, 0x1f71, 0x2ada,
    0x0c4e, 0x2d3c, 0x2033, 0x27e3, 0x2ba9, 0x1f1f, 0x285b, 0x2e48, 0x2c67,
    0x0422, 0x0fef, 0x1b50, 0x17e7, 0x208d, 0x2ab1, 0x04b0, 0x1440, 0x09fb,
    0x17ea, 0x29c7, 0x07aa, 0x13f2, 0x18b8, 0x257d, 0x00a8, 0x1f37, 0x2300,
    0x0fd1, 0x0e90, 0x2b7a, 0x189b, 0x03b4, 0x047a, 0x057c, 0x2ebc, 0x0b67,
    0x0eb2, 0x2014, 0x0fb0, 0x2d75, 0x197b, 0x182e, 0x2eda, 0x2af4, 0x1281,
    0x12a6, 0x1acc, 0x01c5, 0x18ed, 0x2e5f, 0x2145, 0x1b2c, 0x07ef, 0x190d,
    0x2718, 0x2f65, 0x0acf, 0x0f81, 0x206a, 0x070d, 0x0b42, 0x0803, 0x285f,
    0x098f, 0x1803, 0x2dc1, 0x2086, 0x0dc9, 0x2297, 0x2f27, 0x24a5, 0x0733,
    0x26c8, 0x1fee, 0x242b, 0x1d6f, 0x28bf, 0x01aa, 0x0cf3, 0x2494, 0x2ea6,
    0x0ead, 0x07b7, 0x2d2e, 0x2f53, 0x2964, 0x0bc1, 0x25a2, 0x1667, 0x16ec,
    0x0ab2, 0x1e74, 0x0c82, 0x0809, 0x1b08, 0x1afa, 0x0717, 0x2ea3, 0x2a19,
    0x1736, 0x062f, 0x05d1, 0x09c4, 0x2a36, 0x18e6, 0x2b12, 0x2fd0, 0x224a,
    0x1566, 0x049a, 0x2529, 0x2b74, 0x25f2, 0x0d50, 0x0796, 0x0a72, 0x275d,
    0x0d0a, 0x2335, 0x1969, 0x2a91, 0x2b1a, 0x2e07, 0x2f40, 0x2511, 0x17cc,
    0x08b7, 0x039b, 0x040e, 0x1047, 0x183c, 0x0188, 0x0889, 0x01a9, 0x072c,
    0x29ad, 0x0177, 0x2e88, 0x1e1f, 0x1bd6, 0x1e01, 0x1c77, 0x0014, 0x0867,
    0x2a0f, 0x1017, 0x22f2, 0x2eaf, 0x0f6b, 0x0997, 0x163a, 0x0e46, 0x24b3,
    0x2931, 0x0522, 0x1cb6, 0x1c06, 0x2b21, 0x2677, 0x195c, 0x0f77, 0x0864,
    0x18ba, 0x0799, 0x0405, 0x052d, 0x165c, 0x0e28, 0x0764, 0x22f1, 0x1a23,
    0x1e6e, 0x19d9, 0x06c9, 0x026e, 0x1a18, 0x2d85, 0x0f8e, 0x0b83, 0x108b,
    0x2110, 0x2239, 0x1331, 0x1f12, 0x0d41, 0x08f3, 0x22d2, 0x1cd7, 0x1aa9,
    0x0200, 0x1dc3, 0x1e37, 0x2c1f, 0x0b54, 0x00ef, 0x1445, 0x1833, 0x28f5,
    0x2a86, 0x1b6d, 0x2f6f, 0x0697, 0x0196, 0x0a28, 0x2be0, 0x1da0, 0x23d0,
    0x1e86, 0x147e, 0x0bc9, 0x04d4, 0x0938, 0x016c, 0x1ba1, 0x0bd4, 0x2b37,
    0x158e, 0x109b, 0x1d7e, 0x0806, 0x09b3, 0x0be2, 0x0540, 0x2e32, 0x0d4f,
    0x0f8d, 0x05bc, 0x1a7c, 0x2f35, 0x1463, 0x0581, 0x2580, 0x11fd, 0x1fd7,
    0x2f4d, 0x2fbd, 0x272d, 0x11d6, 0x1935, 0x05ff, 0x2381, 0x2fc5, 0x2564,
    0x1470, 0x209b, 0x21ea, 0x2ad2, 0x01c0, 0x2c0b, 0x1d54, 0x1cc5, 0x16d5,
    0x15d4, 0x019c, 0x1c13, 0x0bf0, 0x2621, 0x1c9e, 0x2161, 0x2730, 0x1199,
    0x19d5, 0x2a78, 0x23f2, 0x16cb, 0x1cee, 0x0f87, 0x2f2d, 0x174e, 0x23d7,
    0x0ad1, 0x20d0, 0x2dbe, 0x15dc, 0x1763, 0x046b, 0x05a5, 0x2b9c, 0x1d05,
    0x1666, 0x0498, 0x1a7d, 0x04fb, 0x0eb5, 0x05ee, 0x1050, 0x1c3a, 0x19ec,
    0x1f56, 0x2664, 0x271e, 0x1fd0, 0x06dc, 0x2088, 0x0dce, 0x1e2d, 0x225a,
    0x193f, 0x27f0, 0x0ca6, 0x2185, 0x2288, 0x2b91, 0x0c63, 0x1e78, 0x2493,
    0x28df, 0x2e31, 0x0788, 0x1f58, 0x21a3, 0x2bbd, 0x1ba8, 0x0c85, 0x22e2,
    0x015a, 0x1ecd, 0x0814, 0x2a94, 0x12e8, 0x1812, 0x2041, 0x23a6, 0x007d,
    0x021c, 0x2a0b, 0x107e, 0x0264, 0x1f73, 0x1f7e, 0x0d28, 0x0e05, 0x2d34,
    0x0ba6, 0x2aa4, 0x1007, 0x2684, 0x06b9, 0x0600, 0x1c3c, 0x2b3f, 0x01b6,
    0x2246, 0x1769, 0x0cce, 0x1071, 0x1add, 0x1528, 0x278d, 0x083e, 0x2d35,
    0x2cd3, 0x01a0, 0x266f, 0x06a9, 0x1277, 0x2b49, 0x28b7, 0x145b, 0x0774,
    0x1e47, 0x0d78, 0x2eaa, 0x22fd, 0x2f76, 0x09e4, 0x230c, 0x05c9, 0x0b8d,
    0x2485, 0x07fe, 0x295c, 0x0d8a, 0x1da8, 0x2207, 0x25bf, 0x2def, 0x2cf7,
    0x1198, 0x0eae, 0x0d7e, 0x1edb, 0x1f87, 0x08e4, 0x2c2b, 0x0a21, 0x036f,
    0x0008, 0x2e38, 0x11ab, 0x10cd, 0x212e, 0x0cc4, 0x1971, 0x28c8, 0x076d,
    0x25d7, 0x1c03, 0x01f6, 0x17af, 0x2130, 0x0f06, 0x29dc, 0x1877, 0x2490,
    0x18b0, 0x1dd8, 0x2970, 0x2114, 0x01d2, 0x0406, 0x0096, 0x0288, 0x1f40,
    0x26fe, 0x1612, 0x2f57, 0x08fd, 0x2c97, 0x16b0, 0x0015, 0x09e7, 0x0460,
    0x267f, 0x0317, 0x24f6, 0x24c8, 0x2bba, 0x0a53, 0x0be5, 0x1695, 0x1ee7,
    0x04d9, 0x0ffe, 0x2286, 0x0732, 0x2101, 0x2fb9, 0x1011, 0x1f01, 0x0b0c,
    0x2569, 0x1d1f, 0x1239, 0x151e, 0x0bcc, 0x1629, 0x0e55, 0x1b5a, 0x2c51,
    0x12a2, 0x17ed, 0x075a, 0x2bf1, 0x280e, 0x1522, 0x04e3, 0x06fe, 0x149b,
    0x0ee7, 0x06c6, 0x2abb, 0x1939, 0x1147, 0x0f1d, 0x2963, 0x05fa, 0x2760,
    0x06e3, 0x23d5, 0x2f44, 0x2b02, 0x0361, 0x2591, 0x1432, 0x1c93, 0x11d5,
    0x13d6, 0x06f7, 0x2436, 0x1f9f, 0x0b18, 0x2653, 0x28b5, 0x08cd, 0x1ade,
    0x2557, 0x1d2d, 0x2b79, 0x23eb, 0x1e5b, 0x02ef, 0x126f, 0x2c73, 0x170c,
    0x1e7e, 0x1647, 0x2a1f, 0x2408, 0x2a8b, 0x23ef, 0x2cc7, 0x1c4e, 0x2253,
    0x1964, 0x067a, 0x1a0f, 0x150a, 0x0a3e, 0x01fe, 0x1235, 0x2869, 0x01c2,
    0x1b09, 0x2dbf, 0x2121, 0x21ab, 0x26bc, 0x137b, 0x2fc2, 0x140f, 0x22e1,
    0x1db5, 0x119e, 0x25b4, 0x0b82, 0x1aac, 0x0787, 0x2c0a, 0x016d, 0x2c90,
    0x13af, 0x15ab, 0x09b5, 0x0388, 0x055b, 0x0018, 0x2d9b, 0x0500, 0x091e,
    0x2b3a, 0x0636, 0x113b, 0x0763, 0x1c12, 0x29ee, 0x28f7, 0x01a1, 0x08f5,
    0x26df, 0x1dac, 0x0d5a, 0x115b, 0x1807, 0x0d8d, 0x13da, 0x1e13, 0x02aa,
    0x03d4, 0x1baf, 0x2cb5, 0x1457, 0x202f, 0x1f50, 0x236c, 0x25de, 0x2104,
    0x1b58, 0x161e, 0x0237, 0x0b7d, 0x0eb9, 0x1d0a, 0x0125, 0x0ca0, 0x2a83,
    0x25b8, 0x1b1c, 0x0b81, 0x2442, 0x04f1, 0x0d98, 0x2786, 0x159a, 0x1a1d,
    0x1ffe, 0x2099, 0x0b10, 0x281c, 0x0df4, 0x2aff, 0x20a8, 0x06aa, 0x1d87,
    0x2364, 0x1b07, 0x2231, 0x2158, 0x0f65, 0x19f3, 0x17c6, 0x17d9, 0x23d1,
    0x1fc8, 0x08a5, 0x0edd, 0x2d02, 0x2d00, 0x1596, 0x2fcf, 0x2f29, 0x1108,
    0x232c, 0x1c43, 0x23af, 0x2176, 0x2cb4, 0x2871, 0x2ffa
};

#endif
