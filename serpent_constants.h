/**
 * These are constants defined by the original Serpent authors.
 * They are used for linear transformations (lt), S-Box and
 * permutations used in the Serpent block cipher.
 */

#define ROUNDS 32
#define PHI 0x9e3779b9
//#define max128 0xffffffffffffffffffffffffffffffff


const uint8_t lt_lengths[128]     = {
	7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,2,
	7,3,7,2,7,3,7,2,7,3,7,3,7,3,7,3,6,3,7,3,6,3,7,3,6,3,7,3,7,3,7,3,
	7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,7,3,4,3,7,3,4,3,
	7,3,4,3,7,3,4,3,7,3,4,3,7,3,4,3,7,3,4,3,7,3,6,3,7,3,6,3,7,3,6,3};

// I do not know how to find the inverse LT from the original LT.
const uint8_t lt_lengths_inverse[128] = {
	3,4,2,3,3,4,2,3,3,4,2,3,3,4,2,6,3,4,3,6,3,4,3,6,3,4,3,6,3,5,3,7,
	3,5,3,7,3,5,3,7,3,5,3,7,3,5,3,7,3,5,3,7,3,5,3,7,3,5,3,7,3,5,3,7,
	3,5,3,7,3,5,3,7,3,5,3,7,3,5,3,7,3,5,3,7,3,5,3,7,3,5,3,7,3,5,3,7,
	3,5,3,7,3,5,3,7,3,5,3,7,3,5,3,7,3,5,3,7,3,5,2,7,3,5,2,7,3,5,2,7};

const uint8_t lt_table[610] = {
	0x10,0x34,0x38,0x46,0x53,0x5e,0x69,	0x48,0x72,0x7d,
	0x02,0x09,0x0f,0x1e,0x4c,0x54,0x7e,	0x24,0x5a,0x67,
	0x14,0x38,0x3c,0x4a,0x57,0x62,0x6d,	0x01,0x4c,0x76,
	0x02,0x06,0x0d,0x13,0x22,0x50,0x58,	0x28,0x5e,0x6b,
	0x18,0x3c,0x40,0x4e,0x5b,0x66,0x71,	0x05,0x50,0x7a,
	0x06,0x0a,0x11,0x17,0x26,0x54,0x5c,	0x2c,0x62,0x6f,
	0x1c,0x40,0x44,0x52,0x5f,0x6a,0x75,	0x09,0x54,0x7e,
	0x0a,0x0e,0x15,0x1b,0x2a,0x58,0x60,	0x30,0x66,0x73,
	0x20,0x44,0x48,0x56,0x63,0x6e,0x79,	0x02,0x0d,0x58,
	0x0e,0x12,0x19,0x1f,0x2e,0x5c,0x64,	0x34,0x6a,0x77,
	0x24,0x48,0x4c,0x5a,0x67,0x72,0x7d,	0x06,0x11,0x5c,
	0x12,0x16,0x1d,0x23,0x32,0x60,0x68,	0x38,0x6e,0x7b,
	0x01,0x28,0x4c,0x50,0x5e,0x6b,0x76,	0x0a,0x15,0x60,
	0x16,0x1a,0x21,0x27,0x36,0x64,0x6c,	0x3c,0x72,0x7f,
	0x05,0x2c,0x50,0x54,0x62,0x6f,0x7a,	0x0e,0x19,0x64,
	0x1a,0x1e,0x25,0x2b,0x3a,0x68,0x70,	0x03,0x76,
	0x09,0x30,0x54,0x58,0x66,0x73,0x7e,	0x12,0x1d,0x68,
	0x1e,0x22,0x29,0x2f,0x3e,0x6c,0x74,	0x07,0x7a,
	0x02,0x0d,0x34,0x58,0x5c,0x6a,0x77,	0x16,0x21,0x6c,
	0x22,0x26,0x2d,0x33,0x42,0x70,0x78,	0x0b,0x7e,
	0x06,0x11,0x38,0x5c,0x60,0x6e,0x7b,	0x1a,0x25,0x70,
	0x26,0x2a,0x31,0x37,0x46,0x74,0x7c,	0x02,0x0f,0x4c,
	0x0a,0x15,0x3c,0x60,0x64,0x72,0x7f,	0x1e,0x29,0x74,
	0x00,0x2a,0x2e,0x35,0x3b,0x4a,0x78,	0x06,0x13,0x50,
	0x03,0x0e,0x19,0x64,0x68,0x76,		0x22,0x2d,0x78,
	0x04,0x2e,0x32,0x39,0x3f,0x4e,0x7c,	0x0a,0x17,0x54,
	0x07,0x12,0x1d,0x68,0x6c,0x7a,		0x26,0x31,0x7c,
	0x00,0x08,0x32,0x36,0x3d,0x43,0x52,	0x0e,0x1b,0x58,
	0x0b,0x16,0x21,0x6c,0x70,0x7e,		0x00,0x2a,0x35,
	0x04,0x0c,0x36,0x3a,0x41,0x47,0x56,	0x12,0x1f,0x5c,
	0x02,0x0f,0x1a,0x25,0x4c,0x70,0x74,	0x04,0x2e,0x39,
	0x08,0x10,0x3a,0x3e,0x45,0x4b,0x5a,	0x16,0x23,0x60,
	0x06,0x13,0x1e,0x29,0x50,0x74,0x78,	0x08,0x32,0x3d,
	0x0c,0x14,0x3e,0x42,0x49,0x4f,0x5e,	0x1a,0x27,0x64,
	0x0a,0x17,0x22,0x2d,0x54,0x78,0x7c,	0x0c,0x36,0x41,
	0x10,0x18,0x42,0x46,0x4d,0x53,0x62,	0x1e,0x2b,0x68,
	0x00,0x0e,0x1b,0x26,0x31,0x58,0x7c,	0x10,0x3a,0x45,
	0x14,0x1c,0x46,0x4a,0x51,0x57,0x66,	0x22,0x2f,0x6c,
	0x00,0x04,0x12,0x1f,0x2a,0x35,0x5c,	0x14,0x3e,0x49,
	0x18,0x20,0x4a,0x4e,0x55,0x5b,0x6a,	0x26,0x33,0x70,
	0x04,0x08,0x16,0x23,0x2e,0x39,0x60,	0x18,0x42,0x4d,
	0x1c,0x24,0x4e,0x52,0x59,0x5f,0x6e,	0x2a,0x37,0x74,
	0x08,0x0c,0x1a,0x27,0x32,0x3d,0x64,	0x1c,0x46,0x51,
	0x20,0x28,0x52,0x56,0x5d,0x63,0x72,	0x2e,0x3b,0x78,
	0x0c,0x10,0x1e,0x2b,0x36,0x41,0x68,	0x20,0x4a,0x55,
	0x24,0x5a,0x67,0x76,				0x32,0x3f,0x7c,
	0x10,0x14,0x22,0x2f,0x3a,0x45,0x6c,	0x24,0x4e,0x59,
	0x28,0x5e,0x6b,0x7a,				0x00,0x36,0x43,
	0x14,0x18,0x26,0x33,0x3e,0x49,0x70,	0x28,0x52,0x5d,
	0x2c,0x62,0x6f,0x7e,				0x04,0x3a,0x47,
	0x18,0x1c,0x2a,0x37,0x42,0x4d,0x74,	0x2c,0x56,0x61,
	0x02,0x30,0x66,0x73,				0x08,0x3e,0x4b,
	0x1c,0x20,0x2e,0x3b,0x46,0x51,0x78,	0x30,0x5a,0x65,
	0x06,0x34,0x6a,0x77,				0x0c,0x42,0x4f,
	0x20,0x24,0x32,0x3f,0x4a,0x55,0x7c,	0x34,0x5e,0x69,
	0x0a,0x38,0x6e,0x7b,				0x10,0x46,0x53,
	0x00,0x24,0x28,0x36,0x43,0x4e,0x59,	0x38,0x62,0x6d,
	0x0e,0x3c,0x72,0x7f,				0x14,0x4a,0x57,
	0x04,0x28,0x2c,0x3a,0x47,0x52,0x5d,	0x3c,0x66,0x71,
	0x03,0x12,0x48,0x72,0x76,0x7d,		0x18,0x4e,0x5b,
	0x08,0x2c,0x30,0x3e,0x4b,0x56,0x61,	0x40,0x6a,0x75,
	0x01,0x07,0x16,0x4c,0x76,0x7a,		0x1c,0x52,0x5f,
	0x0c,0x30,0x34,0x42,0x4f,0x5a,0x65,	0x44,0x6e,0x79,
	0x05,0x0b,0x1a,0x50,0x7a,0x7e,		0x20,0x56,0x63};
const uint8_t lt_table_inverse[610] = {
	0x35,0x37,0x48,		0x01,0x05,0x14,0x5a,
	0x0f,0x66,			0x03,0x1f,0x5a,
	0x39,0x3b,0x4c,		0x05,0x09,0x18,0x5e,
	0x13,0x6a,			0x07,0x23,0x5e,
	0x3d,0x3f,0x50,		0x09,0x0d,0x1c,0x62,
	0x17,0x6e,			0x0b,0x27,0x62,
	0x41,0x43,0x54,		0x0d,0x11,0x20,0x66,
	0x1b,0x72,			0x01,0x03,0x0f,0x14,0x2b,0x66,
	0x45,0x47,0x58,		0x11,0x15,0x24,0x6a,
	0x01,0x1f,0x76,		0x05,0x07,0x13,0x18,0x2f,0x6a,
	0x49,0x4b,0x5c,		0x15,0x19,0x28,0x6e,
	0x05,0x23,0x7a,		0x09,0x0b,0x17,0x1c,0x33,0x6e,
	0x4d,0x4f,0x60,		0x19,0x1d,0x2c,0x72,
	0x09,0x27,0x7e,		0x0d,0x0f,0x1b,0x20,0x37,0x72,
	0x51,0x53,0x64,		0x01,0x1d,0x21,0x30,0x76,
	0x02,0x0d,0x2b,		0x01,0x11,0x13,0x1f,0x24,0x3b,0x76,
	0x55,0x57,0x68,		0x05,0x21,0x25,0x34,0x7a,
	0x06,0x11,0x2f,		0x05,0x15,0x17,0x23,0x28,0x3f,0x7a,
	0x59,0x5b,0x6c,		0x09,0x25,0x29,0x38,0x7e,
	0x0a,0x15,0x33,		0x09,0x19,0x1b,0x27,0x2c,0x43,0x7e,
	0x5d,0x5f,0x70,		0x02,0x0d,0x29,0x2d,0x3c,
	0x0e,0x19,0x37,		0x02,0x0d,0x1d,0x1f,0x2b,0x30,0x47,
	0x61,0x63,0x74,		0x06,0x11,0x2d,0x31,0x40,
	0x12,0x1d,0x3b,		0x06,0x11,0x21,0x23,0x2f,0x34,0x4b,
	0x65,0x67,0x78,		0x0a,0x15,0x31,0x35,0x44,
	0x16,0x21,0x3f,		0x0a,0x15,0x25,0x27,0x33,0x38,0x4f,
	0x69,0x6b,0x7c,		0x0e,0x19,0x35,0x39,0x48,
	0x1a,0x25,0x43,		0x0e,0x19,0x29,0x2b,0x37,0x3c,0x53,
	0x00,0x6d,0x6f,		0x12,0x1d,0x39,0x3d,0x4c,
	0x1e,0x29,0x47,		0x12,0x1d,0x2d,0x2f,0x3b,0x40,0x57,
	0x04,0x71,0x73,		0x16,0x21,0x3d,0x41,0x50,
	0x22,0x2d,0x4b,		0x16,0x21,0x31,0x33,0x3f,0x44,0x5b,
	0x08,0x75,0x77,		0x1a,0x25,0x41,0x45,0x54,
	0x26,0x31,0x4f,		0x1a,0x25,0x35,0x37,0x43,0x48,0x5f,
	0x0c,0x79,0x7b,		0x1e,0x29,0x45,0x49,0x58,
	0x2a,0x35,0x53,		0x1e,0x29,0x39,0x3b,0x47,0x4c,0x63,
	0x10,0x7d,0x7f,		0x22,0x2d,0x49,0x4d,0x5c,
	0x2e,0x39,0x57,		0x22,0x2d,0x3d,0x3f,0x4b,0x50,0x67,
	0x01,0x03,0x14,		0x26,0x31,0x4d,0x51,0x60,
	0x32,0x3d,0x5b,		0x26,0x31,0x41,0x43,0x4f,0x54,0x6b,
	0x05,0x07,0x18,		0x2a,0x35,0x51,0x55,0x64,
	0x36,0x41,0x5f,		0x2a,0x35,0x45,0x47,0x53,0x58,0x6f,
	0x09,0x0b,0x1c,		0x2e,0x39,0x55,0x59,0x68,
	0x3a,0x45,0x63,		0x2e,0x39,0x49,0x4b,0x57,0x5c,0x73,
	0x0d,0x0f,0x20,		0x32,0x3d,0x59,0x5d,0x6c,
	0x3e,0x49,0x67,		0x32,0x3d,0x4d,0x4f,0x5b,0x60,0x77,
	0x11,0x13,0x24,		0x36,0x41,0x5d,0x61,0x70,
	0x42,0x4d,0x6b,		0x36,0x41,0x51,0x53,0x5f,0x64,0x7b,
	0x15,0x17,0x28,		0x3a,0x45,0x61,0x65,0x74,
	0x46,0x51,0x6f,		0x3a,0x45,0x55,0x57,0x63,0x68,0x7f,
	0x19,0x1b,0x2c,		0x3e,0x49,0x65,0x69,0x78,
	0x4a,0x55,0x73,		0x03,0x3e,0x49,0x59,0x5b,0x67,0x6c,
	0x1d,0x1f,0x30,		0x42,0x4d,0x69,0x6d,0x7c,
	0x4e,0x59,0x77,		0x07,0x42,0x4d,0x5d,0x5f,0x6b,0x70,
	0x21,0x23,0x34,		0x00,0x46,0x51,0x6d,0x71,
	0x52,0x5d,0x7b,		0x0b,0x46,0x51,0x61,0x63,0x6f,0x74,
	0x25,0x27,0x38,		0x04,0x4a,0x55,0x71,0x75,
	0x56,0x61,0x7f,		0x0f,0x4a,0x55,0x65,0x67,0x73,0x78,
	0x29,0x2b,0x3c,		0x08,0x4e,0x59,0x75,0x79,
	0x03,0x5a,			0x13,0x4e,0x59,0x69,0x6b,0x77,0x7c,
	0x2d,0x2f,0x40,		0x0c,0x52,0x5d,0x79,0x7d,
	0x07,0x5e,			0x00,0x17,0x52,0x5d,0x6d,0x6f,0x7b,
	0x31,0x33,0x44,		0x01,0x10,0x56,0x61,0x7d,
	0x0b,0x62,			0x04,0x1b,0x56,0x61,0x71,0x73,0x7f};
	
	
// there are 8 S-Boxes. Each S-Box definition holds 16 values in 0..15 (stored in a char)
// see https://www.princeton.edu/~rblee/serpent/tsld006.htm for how they were generated
const uint8_t sbox_table[128] = {
	0x3,0x8,0xf,0x1,0xa,0x6,0x5,0xb,0xe,0xd,0x4,0x2,0x7,0x0,0x9,0xc,
	0xf,0xc,0x2,0x7,0x9,0x0,0x5,0xa,0x1,0xb,0xe,0x8,0x6,0xd,0x3,0x4,
	0x8,0x6,0x7,0x9,0x3,0xc,0xa,0xf,0xd,0x1,0xe,0x4,0x0,0xb,0x5,0x2,
	0x0,0xf,0xb,0x8,0xc,0x9,0x6,0x3,0xd,0x1,0x2,0x4,0xa,0x7,0x5,0xe,
	0x1,0xf,0x8,0x3,0xc,0x0,0xb,0x6,0x2,0x5,0x4,0xa,0x9,0xe,0x7,0xd,
	0xf,0x5,0x2,0xb,0x4,0xa,0x9,0xc,0x0,0x3,0xe,0x8,0xd,0x6,0x7,0x1,
	0x7,0x2,0xc,0x5,0x8,0x4,0x6,0xb,0xe,0x9,0x1,0xf,0xd,0x3,0xa,0x0,
	0x1,0xd,0xf,0x0,0xe,0x8,0x2,0xb,0x7,0x4,0xc,0xa,0x9,0x3,0x5,0x6};

/* the inverse table can be calculated from the sbox_table like this:
	uint8_t sbox_table_inverse[128], i;
	for (i = 0; i < 128; i++) {
		sbox_table_inverse[sbox_table[i]] = i;
	}
*/
const uint8_t sbox_table_inverse[128] = {
	0xd,0x3,0xb,0x0,0xa,0x6,0x5,0xc,0x1,0xe,0x4,0x7,0xf,0x9,0x8,0x2,
	0x5,0x8,0x2,0xe,0xf,0x6,0xc,0x3,0xb,0x4,0x7,0x9,0x1,0xd,0xa,0x0,
	0xc,0x9,0xf,0x4,0xb,0xe,0x1,0x2,0x0,0x3,0x6,0xd,0x5,0x8,0xa,0x7,
	0x0,0x9,0xa,0x7,0xb,0xe,0x6,0xd,0x3,0x5,0xc,0x2,0x4,0x8,0xf,0x1,
	0x5,0x0,0x8,0x3,0xa,0x9,0x7,0xe,0x2,0xc,0xb,0x6,0x4,0xf,0xd,0x1,
	0x8,0xf,0x2,0x9,0x4,0x1,0xd,0xe,0xb,0x6,0x5,0x3,0x7,0xc,0xa,0x0,
	0xf,0xa,0x1,0xd,0x5,0x3,0x6,0x0,0x4,0x9,0xe,0x7,0x2,0xc,0x8,0xb,
	0x3,0x0,0x6,0xd,0x9,0xe,0xf,0x8,0x5,0xc,0xb,0x7,0xa,0x1,0x4,0x2,};

// 
uint8_t initial_permutation_table[128] = {
	0x00,0x20,0x40,0x60,0x01,0x21,0x41,0x61,0x02,0x22,0x42,0x62,0x03,0x23,0x43,0x63,
	0x04,0x24,0x44,0x64,0x05,0x25,0x45,0x65,0x06,0x26,0x46,0x66,0x07,0x27,0x47,0x67,
	0x08,0x28,0x48,0x68,0x09,0x29,0x49,0x69,0x0a,0x2a,0x4a,0x6a,0x0b,0x2b,0x4b,0x6b,
	0x0c,0x2c,0x4c,0x6c,0x0d,0x2d,0x4d,0x6d,0x0e,0x2e,0x4e,0x6e,0x0f,0x2f,0x4f,0x6f,
	0x10,0x30,0x50,0x70,0x11,0x31,0x51,0x71,0x12,0x32,0x52,0x72,0x13,0x33,0x53,0x73,
	0x14,0x34,0x54,0x74,0x15,0x35,0x55,0x75,0x16,0x36,0x56,0x76,0x17,0x37,0x57,0x77,
	0x18,0x38,0x58,0x78,0x19,0x39,0x59,0x79,0x1a,0x3a,0x5a,0x7a,0x1b,0x3b,0x5b,0x7b,
	0x1c,0x3c,0x5c,0x7c,0x1d,0x3d,0x5d,0x7d,0x1e,0x3e,0x5e,0x7e,0x1f,0x3f,0x5f,0x7f};
uint8_t final_permutation_table[128] = {
	0x00,0x04,0x08,0x0c,0x10,0x14,0x18,0x1c,0x20,0x24,0x28,0x2c,0x30,0x34,0x38,0x3c,
	0x40,0x44,0x48,0x4c,0x50,0x54,0x58,0x5c,0x60,0x64,0x68,0x6c,0x70,0x74,0x78,0x7c,
	0x01,0x05,0x09,0x0d,0x11,0x15,0x19,0x1d,0x21,0x25,0x29,0x2d,0x31,0x35,0x39,0x3d,
	0x41,0x45,0x49,0x4d,0x51,0x55,0x59,0x5d,0x61,0x65,0x69,0x6d,0x71,0x75,0x79,0x7d,
	0x02,0x06,0x0a,0x0e,0x12,0x16,0x1a,0x1e,0x22,0x26,0x2a,0x2e,0x32,0x36,0x3a,0x3e,
	0x42,0x46,0x4a,0x4e,0x52,0x56,0x5a,0x5e,0x62,0x66,0x6a,0x6e,0x72,0x76,0x7a,0x7e,
	0x03,0x07,0x0b,0x0f,0x13,0x17,0x1b,0x1f,0x23,0x27,0x2b,0x2f,0x33,0x37,0x3b,0x3f,
	0x43,0x47,0x4b,0x4f,0x53,0x57,0x5b,0x5f,0x63,0x67,0x6b,0x6f,0x73,0x77,0x7b,0x7f};
