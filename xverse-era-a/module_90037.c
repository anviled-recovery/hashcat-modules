/**
 * Author......: anviled.io (based on hashcat's v8 module layout)
 * License.....: MIT
 *
 * Mode 90037 - Xverse Wallet, legacy era A (seedless)
 *
 * Era A (ext v0.6-v0.21, 2021-2022) predates the SeedVault:
 *
 *   argonHash = argon2i(password, utf8(localStorage salt hex-string),
 *                       t=3, m=65536, p=4, hashLen=48)
 *   dk        = PBKDF2-HMAC-SHA512(utf8(hex(argonHash)), salt16, 100000, 48)
 *               -> encKey[0:16] | macKey[16:32] | iv[32:48]
 *   ct        = AES-128-CBC(encKey, iv, pkcs7(bip39 entropy))
 *   blob      = hex(salt16 || HMAC-SHA256(macKey, salt16||ct) || ct)
 *
 * The stored HMAC is the verifier (2^-256), so the line carries the two
 * salts, the HMAC and the full ciphertext (32 bytes for a 12-word seed,
 * 48 for a 24-word one) — still no seed material in it.
 *
 * Hash line grammar:
 *   $xverse-a$<argon2 salt hex string, 32>$<blob salt16 hex>$<hmac hex, 64>$<ct hex, 64|96>
 *
 * NOTE: the argon2 salt is the 32 ASCII characters of the localStorage
 * `salt` hex string itself (utf8-of-hex-string quirk).
 *
 * Requires hashcat v8.0.0+ (argon2 framework).
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"
#include "argon2_common.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Xverse Wallet, legacy (seedless)";
static const u64   KERN_TYPE      = 90037;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_DIMY_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_MP_MULTI_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "xverse-test-1";
static const char *ST_HASH        = "$xverse-a$000102030405060708090a0b0c0d0e0f$000102030405060708090a0b0c0d0e0f$95e1fb1d5819ecf67aa59841c4cd36167e7c85af4542919406604ff3ae42acb1$e98153feb917447181271c81b0676bd24523145cfc1a03d43ba5bcdef9c60cf7";

#include "hooks_common.c"

// this must exist so that argon2_common.c can work with correct sizes

typedef struct merged_options
{
  argon2_options_t argon2_options;

  u32 salt_str[8];   // the 32 ascii chars of the localStorage salt hex string
  u32 blob_salt[4];  // 16-byte salt16 from the blob (BE words)
  u32 hmac[8];       // 32-byte HMAC-SHA256 verifier (BE words)
  u32 ct[12];        // full ciphertext: 32 bytes (12 words) or 48 (24 words)
  u32 ct_len;

} merged_options_t;

#include "argon2_common.c"

static const char *SIGNATURE_XVERSE_A = "$xverse-a$";

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "This mode reads the Xverse legacy encrypted seed (two salts, the HMAC verifier and the ciphertext), which contains no readable seed material. The password is verified against the stored HMAC-SHA256. Requires hashcat v8.0.0 or newer";
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (merged_options_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = 4; // not needed here

  return tmp_size;
}

static u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 1;

  return pw_min;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  merged_options_t *merged_options = (merged_options_t *) esalt_buf;

  argon2_options_t *argon2_options = &merged_options->argon2_options;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_XVERSE_A;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 32;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '$';
  token.len[2]     = 32;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len[3]     = 64;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len_min[4] = 64;
  token.len_max[4] = 96;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  memset (merged_options, 0, sizeof (merged_options_t));

  // argon2i parameters (fixed by the wallet)

  argon2_options->type                = 1;     // argon2i
  argon2_options->version             = 0x13;  // v=19
  argon2_options->iterations          = 3;
  argon2_options->parallelism         = 4;
  argon2_options->memory_usage_in_kib = 65536;

  argon2_options->segment_length      = MAX (2, (argon2_options->memory_usage_in_kib / (ARGON2_SYNC_POINTS * argon2_options->parallelism)));
  argon2_options->lane_length         = argon2_options->segment_length * ARGON2_SYNC_POINTS;
  argon2_options->memory_block_count  = argon2_options->lane_length * argon2_options->parallelism;

  argon2_options->digest_len          = 48;

  salt->salt_iter = argon2_options->iterations * ARGON2_SYNC_POINTS;
  salt->salt_dimy = argon2_options->parallelism;

  salt->salt_buf_pc[0] = argon2_options->memory_usage_in_kib;
  salt->salt_buf_pc[1] = argon2_options->parallelism;

  // argon2 salt: the 32 ASCII characters of the localStorage salt hex
  // string itself. The kernel reads it from the esalt; salt_buf carries a
  // synthetic UNIQUE salt (argon salt + first 16 hmac chars) so two blobs
  // sharing a localStorage salt stay separate salts.

  const u8 *salt_pos = token.buf[1];

  memcpy (merged_options->salt_str, salt_pos, 32);

  u8 *salt_out = (u8 *) salt->salt_buf;

  memcpy (salt_out, salt_pos, 32);

  const u8 *hmac_pos_pre = token.buf[3];

  memcpy (salt_out + 32, hmac_pos_pre, 16);

  salt->salt_len = 48;

  // blob salt16 (16 bytes hex -> BE words)

  const u8 *bsalt_pos = token.buf[2];
  const int bsalt_len = token.len[2];

  u8 tmp_buf[48];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  hex_decode (bsalt_pos, bsalt_len, tmp_buf);

  memcpy ((u8 *) merged_options->blob_salt, tmp_buf, 16);

  for (u32 i = 0; i < 4; i++)
  {
    merged_options->blob_salt[i] = byte_swap_32 (merged_options->blob_salt[i]);
  }

  // hmac (32 bytes hex -> BE words)

  const u8 *hmac_pos = token.buf[3];
  const int hmac_len = token.len[3];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  hex_decode (hmac_pos, hmac_len, tmp_buf);

  memcpy ((u8 *) merged_options->hmac, tmp_buf, 32);

  for (u32 i = 0; i < 8; i++)
  {
    merged_options->hmac[i] = byte_swap_32 (merged_options->hmac[i]);
  }

  // ciphertext (64 or 96 hex -> BE words)

  const u8 *ct_pos = token.buf[4];
  const int ct_len = token.len[4];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  const int ct_bytes = hex_decode (ct_pos, ct_len, tmp_buf);

  if (ct_bytes != 32 && ct_bytes != 48) return (PARSER_CT_LENGTH);

  memcpy ((u8 *) merged_options->ct, tmp_buf, ct_bytes);

  const u32 words = ct_bytes / 4;

  for (u32 i = 0; i < words; i++)
  {
    merged_options->ct[i] = byte_swap_32 (merged_options->ct[i]);
  }

  merged_options->ct_len = ct_bytes;

  // digest = the hmac verifier itself

  digest[0] = merged_options->hmac[0];
  digest[1] = merged_options->hmac[1];
  digest[2] = merged_options->hmac[2];
  digest[3] = merged_options->hmac[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const merged_options_t *merged_options = (const merged_options_t *) esalt_buf;

  u8 salt_str[32+1];

  memset (salt_str, 0, sizeof (salt_str));

  memcpy (salt_str, merged_options->salt_str, 32);

  u32 tmp_buf[12];

  for (u32 i = 0; i < 4; i++) tmp_buf[i] = byte_swap_32 (merged_options->blob_salt[i]);

  u8 bsalt_hex[32+1];

  memset (bsalt_hex, 0, sizeof (bsalt_hex));

  hex_encode ((const u8 *) tmp_buf, 16, bsalt_hex);

  for (u32 i = 0; i < 8; i++) tmp_buf[i] = byte_swap_32 (merged_options->hmac[i]);

  u8 hmac_hex[64+1];

  memset (hmac_hex, 0, sizeof (hmac_hex));

  hex_encode ((const u8 *) tmp_buf, 32, hmac_hex);

  const u32 words = merged_options->ct_len / 4;

  for (u32 i = 0; i < words; i++) tmp_buf[i] = byte_swap_32 (merged_options->ct[i]);

  u8 ct_hex[96+1];

  memset (ct_hex, 0, sizeof (ct_hex));

  hex_encode ((const u8 *) tmp_buf, merged_options->ct_len, ct_hex);

  return snprintf (line_buf, line_size, "%s%s$%s$%s$%s",
    SIGNATURE_XVERSE_A,
    salt_str,
    bsalt_hex,
    hmac_hex,
    ct_hex);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_cost           = argon2_module_benchmark_cost;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = argon2_module_extra_buffer_size;
  module_ctx->module_extra_tuningdb_block     = argon2_module_extra_tuningdb_block;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = argon2_module_jit_build_options;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
