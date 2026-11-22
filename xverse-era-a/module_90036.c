/**
 * Author......: anviled.io (based on hashcat's v8 module layout)
 * License.....: MIT
 *
 * Mode 90036 - Xverse Wallet (seedless)
 *
 * Xverse eras B (SeedVault, ext v0.22-v0.49) and C (MasterVault, v0.50+)
 * derive the vault key as:
 *
 *   passwordHash = argon2id(password, utf8(passwordSalt-hex-string),
 *                           t=3, m=65536, p=4, hashLen=16)
 *   key          = utf8(hex(passwordHash))          (32 ascii bytes)
 *   blob         = iv(16) || AES-256-GCM(key, iv).ct || tag
 *
 * Era B encrypts the bip39 entropy as a hex string, so the 32-byte sample
 * must be [0-9a-f]{32} (2^-128). Era C encrypts the vault JSON
 * {"seedEncryptionKey":"<32hex>",...}, so the sample starts with
 * {"seedEncryptionKey":" followed by hex chars. The GCM tag is not needed
 * (CTR prefix decrypt); the line carries no seed material.
 *
 * Hash line grammar:
 *   $xverse$<b|c>$<passwordSalt hex string, 64>$<iv hex, 32>$<first 32 ct bytes hex, 64>
 *
 * NOTE: the argon2 salt is the 64 ASCII characters of the passwordSalt hex
 * string itself (utf8-of-hex-string quirk), not the decoded bytes.
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
static const char *HASH_NAME      = "Xverse Wallet (seedless)";
static const u64   KERN_TYPE      = 90036;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_DIMY_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_MP_MULTI_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "xverse-test-1";
static const char *ST_HASH        = "$xverse$b$000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f$000102030405060708090a0b0c0d0e0f$0f3cc94004353883527f1b2d71f719b0257b674f194ea8cccc796b8d967a0d2c";

#include "hooks_common.c"

// this must exist so that argon2_common.c can work with correct sizes

typedef struct merged_options
{
  argon2_options_t argon2_options;

  u32 era;           // 0 = b (entropy hex), 1 = c (vault JSON)
  u32 salt_str[16];  // the 64 ascii chars of the passwordSalt hex string
  u32 iv_buf[4];     // 16-byte GCM iv
  u32 ct_buf[8];     // first 32 bytes of ciphertext

} merged_options_t;

#include "argon2_common.c"

static const char *SIGNATURE_XVERSE = "$xverse$";

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "This mode reads 32 bytes of the Xverse encrypted vault (plus the salt and IV), so the line carries none of the seed. The password is verified against the shape of the decrypted sample (hex entropy for era b, the vault JSON prefix for era c). Requires hashcat v8.0.0 or newer";
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
  token.signatures_buf[0] = SIGNATURE_XVERSE;

  token.len[0]     = 8;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

  token.sep[2]     = '$';
  token.len[2]     = 64;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len[4]     = 64;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  memset (merged_options, 0, sizeof (merged_options_t));

  // era

  const u8 *era_pos = token.buf[1];

  if (era_pos[0] == 'b')
  {
    merged_options->era = 0;
  }
  else if (era_pos[0] == 'c')
  {
    merged_options->era = 1;
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  // argon2id parameters (fixed by the wallet)

  argon2_options->type                = 2;     // argon2id
  argon2_options->version             = 0x13;  // v=19
  argon2_options->iterations          = 3;
  argon2_options->parallelism         = 4;
  argon2_options->memory_usage_in_kib = 65536;

  argon2_options->segment_length      = MAX (2, (argon2_options->memory_usage_in_kib / (ARGON2_SYNC_POINTS * argon2_options->parallelism)));
  argon2_options->lane_length         = argon2_options->segment_length * ARGON2_SYNC_POINTS;
  argon2_options->memory_block_count  = argon2_options->lane_length * argon2_options->parallelism;

  argon2_options->digest_len          = 16;

  salt->salt_iter = argon2_options->iterations * ARGON2_SYNC_POINTS;
  salt->salt_dimy = argon2_options->parallelism;

  salt->salt_buf_pc[0] = argon2_options->memory_usage_in_kib;
  salt->salt_buf_pc[1] = argon2_options->parallelism;

  // salt: the 64 ASCII characters of the passwordSalt hex string itself
  // (the wallet feeds utf8(hex-string) to argon2, not the decoded bytes).
  //
  // The kernel reads the real salt from the esalt (argon2_init_gp with a
  // local salt_t), while salt_buf carries a synthetic UNIQUE salt — the
  // real salt plus the era letter and 8 iv chars — so that two lines from
  // the same install (era b + era c, or two blobs re-encrypted under the
  // same passwordSalt) stay separate salts and do not trip hashcat's
  // "cannot crack multiple hashes with the same salt" refusal. The argon2
  // cost fields sit on the real salt_t as the framework expects.

  const u8 *salt_pos = token.buf[2];

  memcpy (merged_options->salt_str, salt_pos, 64);

  u8 *salt_out = (u8 *) salt->salt_buf;

  memcpy (salt_out, salt_pos, 64);

  salt_out[64] = era_pos[0];

  const u8 *iv_pos_pre = token.buf[3];

  memcpy (salt_out + 65, iv_pos_pre, 8);

  salt->salt_len = 73;

  // iv (16 bytes hex)

  const u8 *iv_pos = token.buf[3];
  const int iv_len = token.len[3];

  u8 tmp_buf[32];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  hex_decode (iv_pos, iv_len, tmp_buf);

  memcpy ((u8 *) merged_options->iv_buf, tmp_buf, 16);

  merged_options->iv_buf[0] = byte_swap_32 (merged_options->iv_buf[0]);
  merged_options->iv_buf[1] = byte_swap_32 (merged_options->iv_buf[1]);
  merged_options->iv_buf[2] = byte_swap_32 (merged_options->iv_buf[2]);
  merged_options->iv_buf[3] = byte_swap_32 (merged_options->iv_buf[3]);

  // ciphertext sample (first 32 bytes hex)

  const u8 *ct_pos = token.buf[4];
  const int ct_len = token.len[4];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  hex_decode (ct_pos, ct_len, tmp_buf);

  memcpy ((u8 *) merged_options->ct_buf, tmp_buf, 32);

  for (u32 i = 0; i < 8; i++)
  {
    merged_options->ct_buf[i] = byte_swap_32 (merged_options->ct_buf[i]);
  }

  // formality digest: first 16 ct bytes

  digest[0] = merged_options->ct_buf[0];
  digest[1] = merged_options->ct_buf[1];
  digest[2] = merged_options->ct_buf[2];
  digest[3] = merged_options->ct_buf[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const merged_options_t *merged_options = (const merged_options_t *) esalt_buf;

  u8 salt_str[64+1];

  memset (salt_str, 0, sizeof (salt_str));

  memcpy (salt_str, merged_options->salt_str, 64);

  u32 tmp_iv_buf[4];

  tmp_iv_buf[0] = byte_swap_32 (merged_options->iv_buf[0]);
  tmp_iv_buf[1] = byte_swap_32 (merged_options->iv_buf[1]);
  tmp_iv_buf[2] = byte_swap_32 (merged_options->iv_buf[2]);
  tmp_iv_buf[3] = byte_swap_32 (merged_options->iv_buf[3]);

  u8 iv_hex[32+1];

  memset (iv_hex, 0, sizeof (iv_hex));

  hex_encode ((const u8 *) tmp_iv_buf, 16, iv_hex);

  u32 tmp_ct_buf[8];

  for (u32 i = 0; i < 8; i++) tmp_ct_buf[i] = byte_swap_32 (merged_options->ct_buf[i]);

  u8 ct_hex[64+1];

  memset (ct_hex, 0, sizeof (ct_hex));

  hex_encode ((const u8 *) tmp_ct_buf, 32, ct_hex);

  return snprintf (line_buf, line_size, "%s%c$%s$%s$%s",
    SIGNATURE_XVERSE,
    (merged_options->era == 1) ? 'c' : 'b',
    salt_str,
    iv_hex,
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
