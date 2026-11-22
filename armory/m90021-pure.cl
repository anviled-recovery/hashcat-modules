/**
 * Author......: anviled.io (based on hashcat's v8 kernel layout)
 * License.....: MIT
 *
 * Mode 90021 - Armory Wallet (ROMix + AES-256-CFB + secp256k1)
 *
 * ROMix (Armory EncryptionUtils.cpp):
 *   one_iter(key): V[0] = SHA512(key + salt); V[i+1] = SHA512(V[i])
 *                  until memoryBytes are filled;
 *                  X = V[seq-1];
 *                  seq/2 times: idx = LE32(X[60:64]) % seq;
 *                               X = SHA512(X XOR V[idx])
 *                  output X[0:32]
 *   DeriveKey: masterKey = password; repeat one_iter numIterations times.
 *
 * init: ROMix iteration 1   (password + salt)
 * loop: ROMix iterations 2+ (current key + salt), one iteration per call
 * comp: AES-256-CFB decrypt -> privkey * G -> hash160(uncompressed pubkey)
 *       -> compare the address hash160
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#include M2S(INCLUDE_PATH/inc_bitcoin_address.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct armory_esalt
{
  u32 memBytes;
  u32 iterations;
  u32 salt[8];
  u32 addr20[5];
  u32 iv[4];
  u32 enckey[8];

} armory_esalt_t;

typedef struct armory_tmp
{
  u32 key[8];

} armory_tmp_t;

DECLSPEC void sha512_u64 (PRIVATE_AS sha512_ctx_t *ctx, PRIVATE_AS u64 out[8])
{
  sha512_final (ctx);

  out[0] = ctx->h[0];
  out[1] = ctx->h[1];
  out[2] = ctx->h[2];
  out[3] = ctx->h[3];
  out[4] = ctx->h[4];
  out[5] = ctx->h[5];
  out[6] = ctx->h[6];
  out[7] = ctx->h[7];
}

// one full ROMix iteration over the per-gid V table in the extra buffer.
// key_in: key bytes as BE u32 words (key_len bytes), salt as BE u32 words.
DECLSPEC void armory_one_iter (PRIVATE_AS u32 key_io[8], const int key_len, PRIVATE_AS const u32 salt[8], GLOBAL_AS u32 *V, const u32 memBytes)
{
  const u32 seq = memBytes / 64;

  sha512_ctx_t ctx;

  u64 h[8];

  // V[0] = SHA512(key || salt)

  sha512_init (&ctx);
  sha512_update (&ctx, key_io, key_len);
  sha512_update (&ctx, salt, 32);
  sha512_u64 (&ctx, h);

  for (u32 j = 0; j < 8; j++)
  {
    V[j * 2 +  0] = (u32) (h[j] >> 32);
    V[j * 2 +  1] = (u32) (h[j] >>  0);
  }

  // V[i+1] = SHA512(V[i]) for i in 1..seq-1

  for (u32 i = 1; i < seq; i++)
  {
    sha512_init (&ctx);
    sha512_update_global (&ctx, V + (i - 1) * 16, 64);
    sha512_u64 (&ctx, h);

    GLOBAL_AS u32 *cur = V + i * 16;

    for (u32 j = 0; j < 8; j++)
    {
      cur[j * 2 +  0] = (u32) (h[j] >> 32);
      cur[j * 2 +  1] = (u32) (h[j] >>  0);
    }
  }

  // X = V[seq-1]

  u32 X[16];

  GLOBAL_AS const u32 *last = V + (seq - 1) * 16;

  for (u32 j = 0; j < 16; j++) X[j] = last[j];

  // lookup loop: idx = LE32(X[60:64]) % seq; X = SHA512(X XOR V[idx])

  for (u32 i = 0; i < (seq / 2); i++)
  {
    const u32 idx = hc_swap32_S (X[15]) % seq;

    GLOBAL_AS const u32 *Vi = V + idx * 16;

    for (u32 j = 0; j < 16; j++) X[j] ^= Vi[j];

    sha512_init (&ctx);
    sha512_update (&ctx, X, 64);
    sha512_u64 (&ctx, h);

    for (u32 j = 0; j < 8; j++)
    {
      X[j * 2 +  0] = (u32) (h[j] >> 32);
      X[j * 2 +  1] = (u32) (h[j] >>  0);
    }
  }

  // key = X[0:32] (BE u32 words of the first 32 bytes)

  key_io[0] = X[0];
  key_io[1] = X[1];
  key_io[2] = X[2];
  key_io[3] = X[3];
  key_io[4] = X[4];
  key_io[5] = X[5];
  key_io[6] = X[6];
  key_io[7] = X[7];
}

KERNEL_FQ void m90021_init (KERN_ATTR_TMPS_ESALT (armory_tmp_t, armory_esalt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;
  if (gid >= 32) return; // extra buffer sized for 32 work items

  GLOBAL_AS const armory_esalt_t *es = &esalt_bufs[DIGESTS_OFFSET_HOST];

  // password as BE u32 words

  u32 w[16] = { 0 };

  const int w_len = pws[gid].pw_len;

  for (u32 i = 0; i < 16; i++) w[i] = hc_swap32_S (pws[gid].i[i]);

  // salt as BE u32 words (es->salt is raw LE bytes)

  u32 salt[8];

  for (u32 i = 0; i < 8; i++) salt[i] = hc_swap32_S (es->salt[i]);

  GLOBAL_AS u8 *Vb;
  switch (gid & 3)
  {
    case 0: Vb = (GLOBAL_AS u8 *) d_extra0_buf; break;
    case 1: Vb = (GLOBAL_AS u8 *) d_extra1_buf; break;
    case 2: Vb = (GLOBAL_AS u8 *) d_extra2_buf; break;
    case 3: Vb = (GLOBAL_AS u8 *) d_extra3_buf; break;
  }

  GLOBAL_AS u32 *V = (GLOBAL_AS u32 *) (Vb + ((gid >> 2) * (u64) es->memBytes));

  armory_one_iter (w, w_len, salt, V, es->memBytes);

  for (u32 i = 0; i < 8; i++) tmps[gid].key[i] = w[i];
}

KERNEL_FQ void m90021_loop (KERN_ATTR_TMPS_ESALT (armory_tmp_t, armory_esalt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;
  if (gid >= 32) return; // extra buffer sized for 32 work items

  GLOBAL_AS const armory_esalt_t *es = &esalt_bufs[DIGESTS_OFFSET_HOST];

  u32 salt[8];

  for (u32 i = 0; i < 8; i++) salt[i] = hc_swap32_S (es->salt[i]);

  u32 key[8];

  for (u32 i = 0; i < 8; i++) key[i] = tmps[gid].key[i];

  GLOBAL_AS u8 *Vb2;
  switch (gid & 3)
  {
    case 0: Vb2 = (GLOBAL_AS u8 *) d_extra0_buf; break;
    case 1: Vb2 = (GLOBAL_AS u8 *) d_extra1_buf; break;
    case 2: Vb2 = (GLOBAL_AS u8 *) d_extra2_buf; break;
    case 3: Vb2 = (GLOBAL_AS u8 *) d_extra3_buf; break;
  }

  GLOBAL_AS u32 *V = (GLOBAL_AS u32 *) (Vb2 + ((gid >> 2) * (u64) es->memBytes));

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    armory_one_iter (key, 32, salt, V, es->memBytes);
  }

  for (u32 i = 0; i < 8; i++) tmps[gid].key[i] = key[i];
}

KERNEL_FQ void m90021_comp (KERN_ATTR_TMPS_ESALT (armory_tmp_t, armory_esalt_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  GLOBAL_AS const armory_esalt_t *es = &esalt_bufs[DIGESTS_OFFSET_HOST];

  u32 key[8];

  for (u32 i = 0; i < 8; i++) key[i] = tmps[gid].key[i];

  /**
   * AES-256-CFB decrypt the 32-byte encrypted private key.
   * CFB decryption uses the ENCRYPTION schedule:
   *   pt_i = ct_i XOR AES_enc(ct_{i-1}), ct_{-1} = iv
   */

  u32 ks[60];

  AES256_set_encrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3);

  u32 prev[4];

  prev[0] = es->iv[0];
  prev[1] = es->iv[1];
  prev[2] = es->iv[2];
  prev[3] = es->iv[3];

  u32 pt[8];

  for (u32 blk = 0; blk < 2; blk++)
  {
    u32 stream[4];

    aes256_encrypt (ks, prev, stream, s_te0, s_te1, s_te2, s_te3, s_te4);

    GLOBAL_AS const u32 *ct = es->enckey + blk * 4;

    pt[blk * 4 + 0] = ct[0] ^ stream[0];
    pt[blk * 4 + 1] = ct[1] ^ stream[1];
    pt[blk * 4 + 2] = ct[2] ^ stream[2];
    pt[blk * 4 + 3] = ct[3] ^ stream[3];

    prev[0] = ct[0];
    prev[1] = ct[1];
    prev[2] = ct[2];
    prev[3] = ct[3];
  }

  /**
   * secp256k1: pubkey = privkey * G -> hash160 of the uncompressed form.
   * point_mul_xy wants the scalar little-endian-limb (k[0] = lowest limb):
   * reverse the word order and byte-swap each word.
   */

  for (u32 i = 0; i < 4; i++)
  {
    const u32 t = hc_swap32_S (pt[i]);
    pt[i] = hc_swap32_S (pt[7 - i]);
    pt[7 - i] = t;
  }

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  u32 x[8];
  u32 y[8];

  point_mul_xy (x, y, pt, &preG);

  u32 h160[5];

  hash160_pubkey_uncompressed (h160, x, y);

  // digest = the first 16 bytes of the address hash160 as BE words

  const u32 r0 = hc_swap32_S (h160[0]);
  const u32 r1 = hc_swap32_S (h160[1]);
  const u32 r2 = hc_swap32_S (h160[2]);
  const u32 r3 = hc_swap32_S (h160[3]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
