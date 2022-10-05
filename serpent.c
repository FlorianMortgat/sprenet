/*
This implements the Serpent block cipher as designed by
    Ross Anderson
    Eli  Biham
    Lars Knudsen

using a fixed key length of 256 bits, a fixed
block size of 128 bits.

This implementation is inspired by the python reference
implementation by
    Frank Stajano
(except my version doesn’t use bitslice).

This library also includes a CTR (counter) mode of operation
as well as key geneation facilities that were not present in
the original Serpent submission.

    Florian Mortgat, 2017

Note: most functions use a fixed-size state object for storing
input, intermediate values and output. This makes this library
thread-unsafe (more precisely: do not use the same SC object
across threads).

Note: most functions use a predetermined buffer size and do not
check bounds. Check bounds before using them.
*/

#include "stdint.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"
#include "serpent_constants.h"

/*
NIBBLE0 and NIBBLE1 extract 4-bit nibbles from a byte.
NIBBLE0 extracts the 4 least significant bits
NIBBLE1 extracts the 4 most significant bits
*/
#define NIBBLE0(c) ((c)&0xf)
#define NIBBLE1(c) (((c) >> 4) & 0xf)

/*
BITN (number, bit_n) extracts the bit at index 'bit_n' from 'number' (an
unsigned integer) BITN128 does the same except that its input is an array of 16
chars, (?)little endian.
*/
#define BITN(number, bit_n) (((number) >> (bit_n)) & 1)
#define BITN128(array16chars, bit_n)                                           \
  BITN(array16chars[((bit_n) >> 3)], (bit_n)&7)

/*   -- I leave the function versions as a tribute to hours of debugging because
the BITN macro lacked parentheses around bit_n :
#define BITN(number,bit_n) (((number) >> bit_n) & 1)

uint8_t BITN (uint8_t c, uint8_t n) {
        return c >> n & 1;
}
uint8_t BITN128 (uint8_t* source, uint8_t n) {
        return BITN (source [n>>3], n&7);
}
*/

#define SETBITN(variable, bit_n, value)                                        \
  (variable) ^= (((variable) >> (bit_n)&1) ^ (value)) << (bit_n)
#define SETBITN128(arrayptr, bit_n, value)                                     \
  SETBITN((arrayptr)[(bit_n) >> 3], (bit_n)&7, value)

/*
S-Boxes are a fundamental building block of many block ciphers. They can be
implemented as a lookup table using a 4-bit input and returning 4 bits.
*/
#define SBOX(sbox_n, input) sbox_table[((sbox_n)&7) * 16 + ((input)&0xf)]
#define SBOXINVERSE(sbox_n, input)                                             \
  sbox_table_inverse[((sbox_n)&7) * 16 + ((input)&0xf)]

/*
 */
#define INITIALIZE_NONCE(nonce, IV, ctr)                                       \
  memcpy((nonce) + 8, (IV), 8);                                                \
  (nonce)[0] = (uint8_t)(((ctr) >> 0) & 0xff);                                 \
  (nonce)[1] = (uint8_t)(((ctr) >> 8) & 0xff);                                 \
  (nonce)[2] = (uint8_t)(((ctr) >> 16) & 0xff);                                \
  (nonce)[3] = (uint8_t)(((ctr) >> 24) & 0xff)

typedef struct {
  uint8_t key[16];
  uint8_t input[16];
  uint8_t output[16];
  uint8_t sboxed[16];            // SHati
  uint8_t rolling_output[16];    // BHat: both the input and output of the round
                                 // function
  uint8_t subkeys[528];          // 33×16B = 33×128b, originally "K"
  uint8_t permuted_subkeys[528]; // 33*16, originally "KHat"
  uint32_t round_keys[132];      // originally "k"
  uint32_t prekeys[140];         // 132 + 8
  uint8_t key_schedule_OK;       // flag to avoid recomputing the key schedule
} SerpentCipher;

typedef SerpentCipher SC;

void DEBUG_chars(char *title, char *bytes, int size);
void DEBUG_hex(char *title, char *bytes, int size);
uint8_t *SC_encrypt_block(SC *s, uint8_t *block);
uint8_t *SC_decrypt_block(SC *s, uint8_t *block);
void SC_make_subkeys(SC *s);
void SC_round(SC *s, uint8_t round_n);
void SC_round_inverse(SC *s, uint8_t round_n);
void SC_CTR__crypt(SC *s, uint8_t *output_buffer, uint8_t *input_buffer,
                   uint32_t buffer_length, uint8_t IV[8]);
uint8_t *SC_CTR_encrypt(SC *s, uint8_t *output, uint8_t *input, uint32_t length,
                        uint8_t IV[8]);
uint8_t *SC_CTR_decrypt(SC *s, uint8_t *output, uint8_t *input,
                        uint32_t length);

void SC_CTR__crypt(SC *s, uint8_t *output_buffer, uint8_t *input_buffer,
                   uint32_t buffer_length, uint8_t IV[8]) {
  /*
  This is a helper function that is used both by
      SC_CTR_encrypt and SC_CTR_decrypt

  the output buffer length is the same as the input buffer length.

  */
  uint32_t n_full_blocks = buffer_length >> 4;         //  = / 16
  uint8_t n_bytes_in_last_block = buffer_length & 0xf; // = remainder
  uint32_t ctr = 0;
  uint32_t i = 0;
  uint8_t nonce[16] = {};
  uint8_t *xor_block;
  uint8_t *cur_input_block = input_buffer;
  uint8_t *cur_output_block = output_buffer;
  // memset (nonce, 0, 16* sizeof(uint8_t)); // TODO: check if necessary

  while (ctr < n_full_blocks) {
    INITIALIZE_NONCE(nonce, IV, ctr);
    // bytes 8 to 15: initialization vector
    // memcpy (nonce + 8, IV, 8);
    // bytes 0 to 3: the counter (it could go up to 7,
    // but our implementation doesn’t require that since no text
    // larger than 4Gb will ever be passed to that function
    // nonce[0] = (uint8_t) ((ctr >>  0) & 0xff);
    // nonce[1] = (uint8_t) ((ctr >>  8) & 0xff);
    // nonce[2] = (uint8_t) ((ctr >> 16) & 0xff);
    // nonce[3] = (uint8_t) ((ctr >> 24) & 0xff);
    // note: there are 32 unused bits there; this is normal.
    xor_block = SC_encrypt_block(s, nonce);
    for (i = 0; i < 16; i++) {
      cur_output_block[i] = cur_input_block[i] ^ xor_block[i];
    }
    // move the pointer to the next 128b (16B) block.
    cur_input_block += 16;
    cur_output_block += 16;
    ctr++;
  }
  if (n_bytes_in_last_block) {
    INITIALIZE_NONCE(nonce, IV, ctr);
    xor_block = SC_encrypt_block(s, nonce);
    for (i = 0; i < n_bytes_in_last_block; i++) {
      cur_output_block[i] = cur_input_block[i] ^ xor_block[i];
    }
  }
}

uint8_t *SC_CTR_encrypt(SC *s, uint8_t *output, uint8_t *input, uint32_t length,
                        uint8_t IV[8]) {
  /*
  Note: this implementation of the IV generation is satisfying for the intended
  use case (small database storage: the birthday problem is negligible).

  However, it should NOT be used for anything else: randomly generating the
  nonce means that the same nonce can be (and will likely be as the data grows)
  generated twice, which is extremely weak, especially if there is any block
  repetitino (which, again, is bound to happen as data grows).

  https://crypto.stackexchange.com/questions/1849/why-not-use-ctr-with-a-randomized-iv

  Length = the length of the input

  Note: the size of the output buffer must be the size of input plus 8 bytes.

  The IV (initialization vector) needs to be unique, but does not need to be
  completely unpredictable. The IV is given in the ciphertext (i.e. known to any
  attacker).

  If an attacker can predict what IV is going to be used and they already know
  some of the blocks that will be encrypted with the key using that IV, this
  will be little help in retrieving the key.
  */
  uint8_t generate_IV = 1;
  uint8_t i;
  uint8_t timeseed_block[16];
  clock_t timeseed = clock() ^ (clock_t)time(NULL);

  // copies the current time (seconds since epoch) to the timeseed_block buffer
  // (we do not care about endianness here, since all we want is some basic
  // entropy)
  for (i = 0; i < 16; i++)
    timeseed_block[i] = ((uint8_t *)(&timeseed))[i];

  // generates the IV randomly if necessary, using Serpent as our PRNG.
  // note that if SC_CTR_encrypt is used several times within the same
  // second
  for (i = 0; i < 8; i++)
    if (IV[i])
      generate_IV = 0;
  if (generate_IV) {
    SC_encrypt_block(s, timeseed_block);
    for (i = 0; i < 8; i++)
      IV[i] = s->output[i];
  }

  // copy the IV to the output
  memcpy(output, IV, 8 * sizeof(uint8_t));

  // encrypt the input and copy it to the output (leaving 8 bytes for the IV)
  SC_CTR__crypt(s, output + 8, input, length, IV);
  return output;
}
uint8_t *SC_CTR_decrypt(SC *s, uint8_t *output, uint8_t *input,
                        uint32_t length) {
  /*
  Length = the length of the output (= length of the input - 8)
  */
  uint8_t *IV = input;
  SC_CTR__crypt(s, output, input + 8, length, IV);
  return output;
}

SC *SC_new(uint8_t *key);

void SC_destroy(SC *s) { free(s); }

SC *SC_new(uint8_t *key) {
  // unsafe: assumes key has exactly 32 bytes
  SC *s = calloc(1, sizeof(SC));
  uint8_t i;
  // copy the key and create the subkeys
  for (i = 0; i < 32; i++)
    s->key[i] = key[i];
  SC_make_subkeys(s);
  return s;
}

uint32_t rotate_left32(uint32_t input, uint8_t n) {
  return (input << n) | (input >> (32 - n));
}

void apply_linear_transformation128(uint8_t *dest, uint8_t *source,
                                    const uint8_t *table,
                                    const uint8_t *table_lengths) {
  /*
  This linear transformation consists in building a 128b number out of
  another 128b number by xoring several defined bits of the source into one
  bit of the dest.
  Python (pseudocode) version:

  for output_bit_index, input_bits_indices in enumerate
  (linear_transformation_table): output_bit = 0 for input_bit_index in
  input_bits_indices: output_bit ^= BITN (source, input_bit_index) SETBITN
  (dest, output_bit_index, output_bit)

  Note: the C version could be further simplified by using BITN128 for the input
  bit too, at the expense of some performance (perhaps).
  */
  uint8_t
      lt_length; // number of input bits to be xored into the current output bit
  uint8_t bit128_n; // bit index in the 128b source
  // uint8_t bit_n;    // bit index in the current 8b char
  // uint8_t byte_n;   // byte index in the 128b (16B) source
  // uint8_t curchar;  // current char in the input
  uint8_t bit_value;     // final value of the output bit
  uint32_t lt_index = 0; // index in the linear transformation table (0 - 609)
  uint8_t j;

  for (bit128_n = 0; bit128_n < 128; bit128_n++) {
    // split up bit128_n (0-127) into byte_n and bit_n (byte index and
    // bit index in the byte)
    /* byte_n = bit128_n >> 3; */
    /* bit_n = bit128_n & 7; */
    // every 8 bits, update curchar (the current byte)
    /*
    if (bit_n == 0) curchar = source[byte_n];
    bit_value = BITN(curchar, bit_n); // this is not in serpent!!!
    */
    bit_value = 0;
    // not every output bit has the same number of xored input bits
    lt_length = table_lengths[bit128_n];
    // this for could probably be simplified into a while loop
    for (j = 0; j < lt_length; j++, lt_index++) {
      bit_value ^= BITN128(source, table[lt_index]);
    }
    // store the output bit in the destination array
    SETBITN128(dest, bit128_n, bit_value);
  }
}

void apply_permutation128(uint8_t *dest, uint8_t *source, uint8_t *table) {
  /*
  All the bits of source are copied onto dest, but not in the same order.
  The permutation table tells which bits go where.
  */
  uint8_t source_bit_n;
  uint8_t dest_bit_n;
  // uint8_t byte_n;

  // for each bit in the destination, find in the table what
  // bit of the source should be taken and copy it.
  for (dest_bit_n = 0; dest_bit_n < 128; dest_bit_n++) {
    // byte_n = dest_bit_n >> 3;
    source_bit_n = table[dest_bit_n];

    SETBITN128(dest, dest_bit_n, BITN128(source, source_bit_n));
  }
}

void SC_make_subkeys(SC *s) {
  int32_t i;
  uint8_t sbox_n;
  uint8_t *key = s->key;
  int8_t bit_n;
  uint8_t sbox_input, sbox_output;
  uint8_t i4;
  uint32_t *round_keys =
      s->round_keys; // round keys are lower-case "k" in the original
  uint8_t *cur_subkey;
  uint32_t *cur_subkey32b;
  uint8_t *cur_permuted_subkey;

  // alias for s->prekeys with an 8-positions shift.
  uint32_t *prekeys = s->prekeys + 8; // prekeys are called "w" in the original

  // one prekey = 256b (divided in 8 chunks of 32 bits).

  // there are 132 prekey chunks indexed from 0 to 131.
  // they make up 16 prekeys of 256b (each prekey divided in 8 × 32b).

  // chop the key into 8 32b chunks indexed from -8 to -1
  for (i = -8; i < 0; i++) {
    prekeys[i] = *(uint32_t *)(key + 4 * (i + 8));
  }
  // xor + rotate the 132 chunks with various things
  for (i = 0; i < 132; i++) {
    prekeys[i] =
        rotate_left32(prekeys[i - 8] ^ prekeys[i - 5] ^ prekeys[i - 3] ^
                          prekeys[i - 1] ^ PHI ^ (uint32_t)i,
                      11);
  }

  /* PART ABOVE THIS: TESTED OK */

  // for each round plus one, mix using s-boxes.
  for (i = 0; i < ROUNDS + 1; i++) {
    // index of the s-box to use (the &0x1f part is just a faster modulo 32).
    sbox_n = (ROUNDS + 3 - i) &
             0x1f; // 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, etc.
    /*
    another way would be to initialize sbox_n at 3 and to wrap it around using
    modulo 8: sbox_n = 3; for (i = 0; i < ROUNDS+1; i++) {
        // do stuff with sbox_n
        sbox_n = (sbox_n - 1) % 8;
    }
    */

    i4 = i << 2; // just a shorthand for i * 4

    // set round_keys to 0
    round_keys[i4 + 0] = 0;
    round_keys[i4 + 1] = 0;
    round_keys[i4 + 2] = 0;
    round_keys[i4 + 3] = 0;

    // this part is hard to grasp because it is bitslice:
    // using 4 uint32_t, it creates s-boxable nibbles out
    // of the Nth bit of each (vertical "bitslice")
    for (bit_n = 0; bit_n < 32; bit_n++) {
      sbox_input = (BITN(prekeys[i4 + 0], bit_n) << 0 |
                    BITN(prekeys[i4 + 1], bit_n) << 1 |
                    BITN(prekeys[i4 + 2], bit_n) << 2 |
                    BITN(prekeys[i4 + 3], bit_n) << 3);
      sbox_output = SBOX(sbox_n, sbox_input);
      /* DEBUG: all correct values here…
      printf ("sbox_input: %d\n", sbox_input);
      printf ("sbox_output: %d\n", sbox_output);
      printf ("bit 0 of %d: %d ; ", sbox_output, BITN (sbox_output, 0));
      printf ("bit 1 of %d: %d ; ", sbox_output, BITN (sbox_output, 1));
      printf ("bit 2 of %d: %d ; ", sbox_output, BITN (sbox_output, 2));
      printf ("bit 3 of %d: %d ; ", sbox_output, BITN (sbox_output, 3));
      printf ("\n");
      if (bit_n >= 10) return;
      */
      SETBITN(round_keys[i4 + 0], bit_n, BITN(sbox_output, 0));
      SETBITN(round_keys[i4 + 1], bit_n, BITN(sbox_output, 1));
      SETBITN(round_keys[i4 + 2], bit_n, BITN(sbox_output, 2));
      SETBITN(round_keys[i4 + 3], bit_n, BITN(sbox_output, 3));
    }

    // transfer the round_key to the sub_key (is this a bitslice unpacking?)

    cur_subkey = s->subkeys + 16 * i;
    cur_subkey32b = (uint32_t *)cur_subkey;
    *(cur_subkey32b + 0) = round_keys[i4 + 0]; // copying bytes 0-3
    *(cur_subkey32b + 1) = round_keys[i4 + 1]; // copying bytes 4-7
    *(cur_subkey32b + 2) = round_keys[i4 + 2]; // copying bytes 8-11
    *(cur_subkey32b + 3) = round_keys[i4 + 3]; // copying bytes 12-15

    cur_permuted_subkey = s->permuted_subkeys + 16 * i;
    // applying the initial permutation and storing the result in
    // cur_permuted_subkey
    apply_permutation128(cur_permuted_subkey, cur_subkey,
                         initial_permutation_table);
  }
  s->key_schedule_OK = 1;
}

uint8_t *SC_encrypt_block(SC *s, uint8_t *block) {
  // block length: 4*32b
  // key length:   8*32b
  uint32_t i;
  memcpy(s->input, block, 16 * sizeof(uint8_t));
  memset(s->output, 0, 16 * sizeof(uint8_t)); // TODO: check if necessary
  // make subkeys and permuted_subkeys (originally "K" and "KHat")

  // prepare the rolling output (originally "BHat")
  apply_permutation128(s->rolling_output, s->input, initial_permutation_table);
  // for each round: mix keys, apply the round’s S-box and the linear
  // transformation
  for (i = 0; i < ROUNDS; i++) {
    SC_round(s, i);
  }

  // finalize by applying the final permutation
  apply_permutation128(s->output, s->rolling_output, final_permutation_table);

  // it is not necessary that this function returns something, as it modifies
  // s in place, but it feels more intuitive to use it with a return value.
  return s->output;
}

uint8_t *SC_decrypt_block(SC *s, uint8_t *block) {
  uint32_t i;
  memcpy(s->input, block, 16 * sizeof(uint8_t));
  memset(s->output, 0, 16 * sizeof(uint8_t)); // TODO: check if necessary
  apply_permutation128(s->rolling_output, s->input, initial_permutation_table);
  // DEBUG_hex ("BHat:  ", s->rolling_output, 16);
  i = ROUNDS - 1;
  do {
    SC_round_inverse(s, i);
    // printf ("i = %d\n", i);
  } while (i--);
  // DEBUG_hex ("BHat final: ", s->rolling_output, 16);
  apply_permutation128(s->output, s->rolling_output, final_permutation_table);
  return s->output;
}

void SC_round(SC *s, uint8_t round_n) {
  /*
  This round function works on the 128b rolling_output (for both
  input and output) and uses intermediate arrays.
  */
  uint8_t i;
  uint8_t curchar, sboxed_char;
  // mixing each byte
  for (i = 0; i < 16; i++) {
    curchar = s->rolling_output[i];
    // xoring
    curchar ^= s->permuted_subkeys[round_n * 16 + i];
    sboxed_char =
        SBOX(round_n, NIBBLE0(curchar)) | SBOX(round_n, NIBBLE1(curchar)) << 4;
    // s-boxing
    s->sboxed[i] = sboxed_char;
  }
  // if the round is not the last (or the additional pseudo-round): (0-30, not
  // 31 and not 32)
  if (round_n < ROUNDS - 1) {
    // linear transformation
    apply_linear_transformation128(s->rolling_output, s->sboxed, lt_table,
                                   lt_lengths);
  } else if (round_n == ROUNDS - 1) {
    for (i = 0; i < 16; i++) {
      s->rolling_output[i] =
          s->sboxed[i] ^ s->permuted_subkeys[ROUNDS * 16 + i];
    }
  }
}

void SC_round_inverse(SC *s, uint8_t round_n) {
  /*
  This inverse round function works on the 128b rolling_output (for both
  input and output) and uses intermediate arrays.
  */
  uint8_t i;
  uint8_t xored_char;
  uint8_t sboxed_char;
  if (round_n < ROUNDS - 1) {
    // printf ("LT input %d:", round_n); DEBUG_hex ("", s->rolling_output, 16);
    // reversing the linear transformation:
    // from s->input to s->sboxed using the inverse linear transformation
    apply_linear_transformation128(s->sboxed, s->rolling_output,
                                   lt_table_inverse, lt_lengths_inverse);
    // printf ("SHat     %d:", round_n); DEBUG_hex ("", s->sboxed, 16);
  } else if (round_n == ROUNDS - 1) {
    // printf ("LT input %d:", round_n); DEBUG_hex ("", s->rolling_output, 16);
    for (i = 0; i < 16; i++) {
      s->sboxed[i] =
          s->rolling_output[i] ^ s->permuted_subkeys[ROUNDS * 16 + i];
    }
  }
  // unmixing sboxed bytes one after another
  // printf ("SHatInverse: ");
  for (i = 0; i < 16; i++) {
    sboxed_char = s->sboxed[i];
    xored_char = SBOXINVERSE(round_n, NIBBLE0(sboxed_char)) |
                 (SBOXINVERSE(round_n, NIBBLE1(sboxed_char)) << 4);
    xored_char ^= s->permuted_subkeys[round_n * 16 + i];
    // printf ("%d ", xored_char);
    s->rolling_output[i] = xored_char;
  }
  // printf ("\n");
}

// for debugging only: prints out a char array (for comparison with the
// equivalent output in the working python code).
void DEBUG_chars(char *title, char *bytes, int size) {
  int i;
  //printf("%s\n", title);
  for (i = 0; i < size; i++) {
    //printf("%c", bytes[i] >= 32 ? bytes[i] : '*');
  }
  //printf("\n");
}

void DEBUG_hex(char *title, char *bytes, int size) {
  int i;
  //printf("%s: ", title);
  for (i = 0; i < size; i++) {
    if ((uint8_t)bytes[i] < 16);
      //printf("0");
    //printf("%x ", (uint8_t)bytes[i]);
  }
  //printf("\n");
}

void rotate_left_array(uint8_t *input, uint8_t places_bits,
                       uint32_t input_size_bits) {
  uint32_t input_size_chunks = input_size_bits >> 3; // bits / 8
  uint32_t chunk_moves =
      places_bits >> 3; // how many whole chunks will be moved
  uint32_t bit_moves =
      places_bits & 7; // how many bits will be moved in each chunk
  uint32_t bit_moves_c = 8 - bit_moves; // by how many bits a chunk should be
                                        // rshifted to get its lost bits
  // uint32_t* input_as_32 = (uint32_t*) input; // alias using 32b unsigned
  // integer size
  uint32_t lost_bits; // container for bits that will be lshifted out and should
                      // be "appended" to the end
  uint8_t i, j;

  // printf ("input_size_chunks: %d\nchunk_moves: %d\n bit_moves: %d\n",
  // input_size_chunks, chunk_moves, bit_moves);
  if (chunk_moves) {
    // this method is very inefficient, but simple:
    // first rotate chunk by chunk, then rotate the bits
    for (i = 0; i < chunk_moves; i++) {
      lost_bits = input[0];
      for (j = 0; j < input_size_chunks - 1; j++) {
        input[j] = input[j + 1];
      }
      input[input_size_chunks - 1] = lost_bits;
    }

    // then rotate the remaining bits
    if (!bit_moves)
      return;
    rotate_left_array(input, bit_moves, input_size_bits);
  } else {
    if (bit_moves == 0)
      return;
    lost_bits = input[0] >> bit_moves_c;
    for (i = 0; i < input_size_chunks - 1; i++) {
      input[i] = (input[i] << bit_moves) | (input[i + 1] >> bit_moves_c);
    }
    input[input_size_chunks - 1] =
        (input[input_size_chunks - 1] << bit_moves) | lost_bits;
  }
}
/* Problème d’endianness!!!! dans un uint32_t, les octets sont inversés par
rapport à 4 uint8_t

void rotate_left_array(uint8_t* input, uint8_t places_bits, uint32_t
input_size_bits) { uint32_t input_size_chunks = input_size_bits >> 5; // bits /
32 uint32_t chunk_moves = places_bits >> 5; // how many whole chunks will be
moved uint32_t bit_moves = places_bits & 0x1f; // how many bits will be moved in
each chunk uint32_t bit_moves_c = 32 - bit_moves;   // by how many bits a chunk
should be rshifted to get its lost bits uint32_t* input_as_32 = (uint32_t*)
input; // alias using 32b unsigned integer size uint32_t lost_bits; // container
for bits that will be lshifted out and should be "appended" to the end uint8_t
i, j;

    //printf ("input_size_chunks: %d\nchunk_moves: %d\n bit_moves: %d\n",
input_size_chunks, chunk_moves, bit_moves); if (chunk_moves) {
        // this method is very inefficient, but simple:
        // first rotate chunk by chunk, then rotate the bits
        for (i = 0; i < chunk_moves; i++) {
            lost_bits = input_as_32[0];
            for (j = 0; j < input_size_chunks-1; j++) {
                input_as_32[j] = input_as_32[j+1];
            }
            input_as_32[input_size_chunks-1] = lost_bits;
        }

        // then rotate the remaining bits
        if (!bit_moves) return;
        rotate_left_array (input, bit_moves, input_size_bits);
    } else {
        if (bit_moves == 0) return;
        lost_bits = input_as_32[0] >> bit_moves_c;
        DEBUG_chars ("lost bits: ", (uint8_t*)&lost_bits, 4);
        for (i = 0; i < input_size_chunks-1; i++) {
            input_as_32[i] = (input_as_32[i] << bit_moves) | (input_as_32[i+1]
>> bit_moves_c);
        }
        input_as_32[input_size_chunks-1] = (input_as_32[input_size_chunks-1] <<
bit_moves) | lost_bits;
    }
}
*/
