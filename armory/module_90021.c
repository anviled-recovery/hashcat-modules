/**
 * Author......: anviled.io (based on hashcat's v8 module layout)
 * License.....: MIT
 *
 * Mode 90021 - Armory Wallet (ROMix + AES-256-CFB + secp256k1)
 *
 * Armory wallet files carry per-address encrypted private keys:
 *
 *   key     = ROMix(password, salt, memoryBytes, iterations)
 *   privkey = AES-256-CFB-decrypt(key, per-address iv, enc_privkey32)
 *
 * ROMix is Armory's memory-hard SHA-512 KDF (EncryptionUtils.cpp):
 *   one_iter(key): V[0] = SHA512(key + salt); V[i+1] = SHA512(V[i])
 *                  until memoryBytes are filled;
 *                  X = V[seq-1];
 *                  seq/2 times: idx = LE32(X[60:64]) % seq;
 *                               X = SHA512(X XOR V[idx])
 *                  output X[0:32]
 *   DeriveKey: repeat one_iter numIterations times.
 *
 * Verification: privkey * G -> uncompressed pubkey (65 bytes) -> compare
 * with the pubkey stored in the same address entry.
 *
 * Hash line grammar (hex fields):
 *   $armory$<memBytes>$<iterations>$<salt64hex>$<addr20_40hex>$<iv32hex>$<enckey64hex>
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Armory Wallet (ROMix, AES-256-CFB)";
static const u64   KERN_TYPE      = 90021;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "btcr-test-password";
static const char *ST_HASH        = "$armory$2097152$4$61b09f05d1a4f6c1cc2e6508e0555560eeee65097ad04e06fcd502fd086eb6e8$afb9a4b35aafa61e06fab453ed6948a6d76bf6a0$905eaba273f5d5415f7bc027ae3be851$eac854df5cd277722b96275d818165f9225fb2dbc84b36bfeee16978f61522e0";

#include "hooks_common.c"

typedef struct armory_esalt
{
  u32 memBytes;        // up to 32 MiB
  u32 iterations;
  u32 salt[8];         // 32-byte ROMix salt
  u32 addr20[5];       // 20-byte address hash160
  u32 iv[4];           // 16-byte per-address IV
  u32 enckey[8];       // 32-byte encrypted private key

} armory_esalt_t;

typedef struct armory_tmp
{
  u32 key[8];          // current 32-byte ROMix key

} armory_tmp_t;

static const char *SIGNATURE_ARMORY = "$armory$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (armory_esalt_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (armory_tmp_t);

  return tmp_size;
}

u64 module_extra_buffer_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  // the ROMix V table lives here: memoryBytes per work item, 32 work items
  // (module_kernel_accel_max pins the accel at 32, so the backend's
  // extra_buffer_size / kernel_power division lands exactly at memoryBytes
  // per work item)

  const armory_esalt_t *es = (const armory_esalt_t *) hashes->esalts_buf;

  u64 size = (u64) es->memBytes;

  if (size < (1 << 20)) size = (1 << 20);

  return size * 32;
}

u32 module_kernel_accel_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // pin the work item count at 32 so each gets exactly memoryBytes of V
  return 32;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  armory_esalt_t *es = (armory_esalt_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ARMORY;

  token.len[0]     = 8;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 8;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 4;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len[3]     = 64;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len[4]     = 40;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '$';
  token.len[5]     = 32;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '$';
  token.len[6]     = 64;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  memset (es, 0, sizeof (armory_esalt_t));

  es->memBytes   = (u32) hc_strtoul ((const char *) token.buf[1], NULL, 10);
  es->iterations = (u32) hc_strtoul ((const char *) token.buf[2], NULL, 10);

  if ((es->memBytes & 63) != 0) return (PARSER_SALT_VALUE);
  if (es->iterations < 1)       return (PARSER_SALT_ITERATION);

  const u8 *salt_pos  = token.buf[3];
  const u8 *addr_pos  = token.buf[4];
  const u8 *iv_pos    = token.buf[5];
  const u8 *key_pos   = token.buf[6];

  for (u32 i = 0; i < 32; i++) ((u8 *) es->salt)[i]   = hex_to_u8 (salt_pos + i * 2);
  for (u32 i = 0; i < 20; i++) ((u8 *) es->addr20)[i] = hex_to_u8 (addr_pos + i * 2);
  for (u32 i = 0; i < 16; i++) ((u8 *) es->iv)[i]     = hex_to_u8 (iv_pos + i * 2);
  for (u32 i = 0; i < 32; i++) ((u8 *) es->enckey)[i] = hex_to_u8 (key_pos + i * 2);

  // ROMix salt goes to the generic salt buffer for the kernel's message build

  memcpy (salt->salt_buf, es->salt, 32);

  salt->salt_len  = 32;
  salt->salt_iter = es->iterations - 1;

  // digest = the first 16 bytes of the address hash160 as big-endian words
  // (the kernel recomputes them from the decrypted private key)

  const u8 *a = (const u8 *) es->addr20;

  digest[0] = ((u32) a[ 0] << 24) | ((u32) a[ 1] << 16) | ((u32) a[ 2] << 8) | (u32) a[ 3];
  digest[1] = ((u32) a[ 4] << 24) | ((u32) a[ 5] << 16) | ((u32) a[ 6] << 8) | (u32) a[ 7];
  digest[2] = ((u32) a[ 8] << 24) | ((u32) a[ 9] << 16) | ((u32) a[10] << 8) | (u32) a[11];
  digest[3] = ((u32) a[12] << 24) | ((u32) a[13] << 16) | ((u32) a[14] << 8) | (u32) a[15];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const armory_esalt_t *es = (const armory_esalt_t *) esalt_buf;

  char salt_hex[64 + 1];
  char addr_hex[40 + 1];
  char iv_hex[32 + 1];
  char key_hex[64 + 1];

  hex_encode ((const u8 *) es->salt, 32, (u8 *) salt_hex);
  hex_encode ((const u8 *) es->addr20, 20, (u8 *) addr_hex);
  hex_encode ((const u8 *) es->iv, 16, (u8 *) iv_hex);
  hex_encode ((const u8 *) es->enckey, 32, (u8 *) key_hex);

  salt_hex[64] = 0;
  addr_hex[40] = 0;
  iv_hex[32] = 0;
  key_hex[64] = 0;

  return snprintf (line_buf, line_size, "%s%u$%u$%s$%s$%s$%s",
    SIGNATURE_ARMORY,
    es->memBytes,
    es->iterations,
    salt_hex,
    addr_hex,
    iv_hex,
    key_hex);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_extra_buffer_size        = module_extra_buffer_size;
  module_ctx->module_kernel_accel_max         = module_kernel_accel_max;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
}
