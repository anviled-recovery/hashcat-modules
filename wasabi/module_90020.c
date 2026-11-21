/**
 * Author......: anviled.io (based on hashcat's v8 module layout)
 * License.....: MIT
 *
 * Mode 90020 - Wasabi Wallet (BIP-0038 non-EC-multiplied secret)
 *
 * The wallet JSON's EncryptedSecret field is a BIP38 non-EC-multiplied
 * encrypted private key (Base58Check, starts with "6P"):
 *
 *   payload (39 bytes): 0x01 0x42 | flagbyte 0xe0 | addresshash(4) | ct(32)
 *
 *   addresshash = SHA256(SHA256(ascii(P2PKH address)))[0:4]  (scrypt salt)
 *   key         = scrypt(password, addresshash, N=16384, r=8, p=8, 64)
 *   ct          = AES-256-ECB(privkey XOR derivedhalf1, key=derivedhalf2)
 *
 * Verification: privkey -> compressed secp256k1 pubkey -> HASH160 ->
 * Base58 address -> addresshash must match.
 *
 * Hash line grammar:
 *   $wasabi$<the BIP38 Base58Check string, 58 chars>
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"
#include "emu_inc_hash_sha256.h"
#include "emu_inc_hash_base58.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Wasabi Wallet (BIP38 NoEC, scrypt)";
static const u64   KERN_TYPE      = 90020;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "TestingOneTwoThree";
static const char *ST_HASH        = "$wasabi$6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo";

#include "hooks_common.c"

static u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

static const char *SIGNATURE_WASABI = "$wasabi$";

static const u32 SCRYPT_THREADS = 32;

#include "scrypt_common.c"

typedef struct wasabi_esalt
{
  u32 flagbyte;
  u32 addrhash;      // 4-byte BIP38 address hash (= scrypt salt), BE u32
  u32 ct[8];         // 32 bytes of encrypted halves

} wasabi_esalt_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (wasabi_esalt_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  wasabi_esalt_t *es = (wasabi_esalt_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_WASABI;

  token.len[0]     = 8;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]     = 58;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  memset (es, 0, sizeof (wasabi_esalt_t));

  const u8 *b58_pos = token.buf[1];

  u8 bin[48];

  u32 binsz = sizeof (bin);

  if (b58dec (bin, &binsz, b58_pos, 58) == false) return (PARSER_HASH_VALUE);

  if (binsz != 43) return (PARSER_HASH_LENGTH);   // 39 + 4 checksum

  // b58dec right-aligns the decoded blob inside the capacity buffer

  const u8 *payload = bin + (sizeof (bin) - binsz);

  if (b58check (payload, binsz) == false) return (PARSER_HASH_VALUE);

  // BIP38 non-EC-multiplied layout

  if (payload[0] != 0x01 || payload[1] != 0x42) return (PARSER_SIGNATURE_UNMATCHED);

  es->flagbyte = payload[2];

  if ((es->flagbyte & 0x1f) != 0) return (PARSER_HASH_VALUE);   // reserved bits

  es->addrhash = ((u32) payload[3] << 24)
               | ((u32) payload[4] << 16)
               | ((u32) payload[5] <<  8)
               | ((u32) payload[6] <<  0);

  memcpy (es->ct, payload + 7, 32);

  // scrypt settings

  salt->scrypt_N = 16384;
  salt->scrypt_r = 8;
  salt->scrypt_p = 8;

  salt->salt_iter    = salt->scrypt_N;
  salt->salt_repeats = salt->scrypt_p - 1;

  // the 4-byte addresshash doubles as the scrypt salt

  memcpy (salt->salt_buf, payload + 3, 4);

  salt->salt_len = 4;

  // digest = the addresshash (first word), zero-padded

  digest[0] = es->addrhash;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const wasabi_esalt_t *es = (const wasabi_esalt_t *) esalt_buf;

  u8 data[38];

  data[0] = 0x42;
  data[1] = (u8) es->flagbyte;
  data[2] = (u8) (es->addrhash >> 24);
  data[3] = (u8) (es->addrhash >> 16);
  data[4] = (u8) (es->addrhash >>  8);
  data[5] = (u8) (es->addrhash >>  0);

  memcpy (data + 6, es->ct, 32);

  u8 b58_out[80];

  u32 b58_len = sizeof (b58_out);

  if (b58check_enc (b58_out, &b58_len, 0x01, data, 38) == false) return 0;

  return snprintf (line_buf, line_size, "%s%.*s", SIGNATURE_WASABI, (int) b58_len, b58_out);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_benchmark_cost           = scrypt_module_benchmark_cost;
  module_ctx->module_extra_buffer_size        = scrypt_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = scrypt_module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = scrypt_module_extra_tuningdb_block;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = scrypt_module_jit_build_options;
  module_ctx->module_kernel_accel_max         = scrypt_module_kernel_accel_max;
  module_ctx->module_kernel_loops_max         = scrypt_module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = scrypt_module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = scrypt_module_kernel_threads_max;
  module_ctx->module_register_options         = scrypt_module_register_options;
  module_ctx->module_tmp_size                 = scrypt_module_tmp_size;
  module_ctx->module_tune_variants            = scrypt_module_tune_variants;
}
