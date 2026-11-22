/**
 * Author......: anviled.io (based on hashcat's m34000-pure.cl)
 * License.....: MIT
 *
 * Mode 90037 - Xverse Wallet, legacy era A (seedless)
 *
 * argon2i(password, utf8(localStorage salt hex-string), t=3, m=65536, p=4, 48)
 * -> PBKDF2-HMAC-SHA512(utf8(hex(argonHash)), salt16, 100000) -> macKey[16:32]
 * -> verify HMAC-SHA256(macKey, salt16 || ct) against the blob's stored hmac
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_argon2.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct argon2_tmp
{
  u32 state[4];

} argon2_tmp_t;

typedef struct merged_options
{
  argon2_options_t argon2_options;

  u32 salt_str[8];   // the 32 ascii chars of the localStorage salt hex string
  u32 blob_salt[4];  // 16-byte salt16 from the blob (BE words)
  u32 hmac[8];       // 32-byte HMAC-SHA256 verifier (BE words)
  u32 ct[12];        // full ciphertext: 32 bytes (12 words) or 48 (24 words)
  u32 ct_len;

} merged_options_t;

KERNEL_FQ KERNEL_FA void m90037_init (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const merged_options_t *es = &esalt_bufs[DIGESTS_OFFSET_HOST];

  const argon2_options_t argon2_options = es->argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  // the real argon2 salt lives in the esalt (the 32 ascii chars of the
  // localStorage salt hex string); salt_bufs carries a synthetic unique salt

  salt_t s;

  for (u32 i = 0; i < sizeof (salt_t) / 4; i++) ((PRIVATE_AS u32 *) &s)[i] = 0;

  for (u32 i = 0; i < 8; i++) s.salt_buf[i] = es->salt_str[i];

  s.salt_len = 32;

  argon2_init_gp (&pws[gid], &s, &argon2_options, argon2_block);
}

KERNEL_FQ KERNEL_FA void m90037_loop (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);
  const u64 bid = get_group_id (0);
  const u64 lid = get_local_id (1);
  const u64 lsz = get_local_size (1);

  if (bid >= GID_CNT) return;

  const u32 argon2_thread = get_local_id (0);
  const u32 argon2_lsz = get_local_size (0);

  #ifdef ARGON2_PARALLELISM
  LOCAL_VK u64 shuffle_bufs[ARGON2_PARALLELISM][32];
  #else
  LOCAL_VK u64 shuffle_bufs[32][32];
  #endif

  LOCAL_AS u64 *shuffle_buf = shuffle_bufs[lid];

  SYNC_THREADS();

  const u32 bd4 = bid / 4;
  const u32 bm4 = bid % 4;

  GLOBAL_AS void *V;

  switch (bm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST_BID].argon2_options;

  #ifdef IS_APPLE
  // it doesn't work on Apple, so we won't set it up
  #else
  #ifdef ARGON2_PARALLELISM
  argon2_options.parallelism = ARGON2_PARALLELISM;
  #endif
  #endif

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, bd4);

  argon2_pos_t pos;

  pos.pass   = (LOOP_POS / ARGON2_SYNC_POINTS);
  pos.slice  = (LOOP_POS % ARGON2_SYNC_POINTS);

  const u32 lanes = argon2_lane_limit (argon2_options.parallelism, lsz);

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    for (pos.lane = lid; pos.lane < lanes; pos.lane += lsz)
    {
      argon2_fill_segment (argon2_block, &argon2_options, &pos, shuffle_buf, argon2_thread, argon2_lsz);
    }

    SYNC_THREADS ();

    pos.slice++;

    if (pos.slice == ARGON2_SYNC_POINTS)
    {
      pos.slice = 0;
      pos.pass++;
    }
  }
}

KERNEL_FQ KERNEL_FA void m90037_comp (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 gd4 = gid / 4;
  const u32 gm4 = gid % 4;

  GLOBAL_AS void *V;

  switch (gm4)
  {
    case 0: V = d_extra0_buf; break;
    case 1: V = d_extra1_buf; break;
    case 2: V = d_extra2_buf; break;
    case 3: V = d_extra3_buf; break;
  }

  const merged_options_t *es = &esalt_bufs[DIGESTS_OFFSET_HOST];

  const argon2_options_t argon2_options = es->argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  // 48-byte argon2i hash, LE-packed words (blake2b convention)

  u32 ah[16];

  argon2_final (argon2_block, &argon2_options, ah);

  // the PBKDF2 password is the UTF-8 of the lowercase hex of those 48
  // bytes: 96 ascii chars, packed big-endian into words

  u32 w[24];

  for (u32 i = 0; i < 24; i++)
  {
    u32 w4 = 0;

    for (u32 j = 0; j < 4; j++)
    {
      const u32 cidx = i * 4 + j;                                   // hex char index
      const u32 tbyte = (ah[cidx / 8] >> (((cidx / 2) & 3) * 8)) & 0xff;

      u32 nib = (cidx & 1) ? (tbyte & 0xf) : (tbyte >> 4);

      nib += (nib < 10) ? 0x30 : 0x57;                              // 0-9, a-f

      w4 |= nib << ((3 - j) * 8);
    }

    w[i] = w4;
  }

  // PBKDF2-HMAC-SHA512(pw 96B, salt16, 100000) — a single block suffices
  // for the macKey (bytes 16..31 of T1)

  sha512_hmac_ctx_t c0;

  sha512_hmac_init (&c0, w, 96);

  u32 bs[4];

  bs[0] = es->blob_salt[0];
  bs[1] = es->blob_salt[1];
  bs[2] = es->blob_salt[2];
  bs[3] = es->blob_salt[3];

  // U1 = HMAC(pw, salt16 || INT32_BE(1))

  sha512_hmac_ctx_t c1 = c0;

  sha512_hmac_update (&c1, bs, 16);

  u32 one[4] = { 1, 0, 0, 0 };

  sha512_hmac_update (&c1, one, 4);

  sha512_hmac_final (&c1);

  u64 dgst[8];
  u64 out[8];

  dgst[0] = c1.opad.h[0];
  dgst[1] = c1.opad.h[1];
  dgst[2] = c1.opad.h[2];
  dgst[3] = c1.opad.h[3];
  dgst[4] = c1.opad.h[4];
  dgst[5] = c1.opad.h[5];
  dgst[6] = c1.opad.h[6];
  dgst[7] = c1.opad.h[7];

  out[0] = dgst[0];
  out[1] = dgst[1];
  out[2] = dgst[2];
  out[3] = dgst[3];
  out[4] = dgst[4];
  out[5] = dgst[5];
  out[6] = dgst[6];
  out[7] = dgst[7];

  for (u32 i = 1; i < 100000; i++)
  {
    // U = HMAC(pw, U_prev): the message is the previous 64-byte U

    u32 m[16];

    m[ 0] = h32_from_64_S (dgst[0]);
    m[ 1] = l32_from_64_S (dgst[0]);
    m[ 2] = h32_from_64_S (dgst[1]);
    m[ 3] = l32_from_64_S (dgst[1]);
    m[ 4] = h32_from_64_S (dgst[2]);
    m[ 5] = l32_from_64_S (dgst[2]);
    m[ 6] = h32_from_64_S (dgst[3]);
    m[ 7] = l32_from_64_S (dgst[3]);
    m[ 8] = h32_from_64_S (dgst[4]);
    m[ 9] = l32_from_64_S (dgst[4]);
    m[10] = h32_from_64_S (dgst[5]);
    m[11] = l32_from_64_S (dgst[5]);
    m[12] = h32_from_64_S (dgst[6]);
    m[13] = l32_from_64_S (dgst[6]);
    m[14] = h32_from_64_S (dgst[7]);
    m[15] = l32_from_64_S (dgst[7]);

    sha512_hmac_ctx_t cx = c0;

    sha512_hmac_update (&cx, m, 64);

    sha512_hmac_final (&cx);

    dgst[0] = cx.opad.h[0];
    dgst[1] = cx.opad.h[1];
    dgst[2] = cx.opad.h[2];
    dgst[3] = cx.opad.h[3];
    dgst[4] = cx.opad.h[4];
    dgst[5] = cx.opad.h[5];
    dgst[6] = cx.opad.h[6];
    dgst[7] = cx.opad.h[7];

    out[0] ^= dgst[0];
    out[1] ^= dgst[1];
    out[2] ^= dgst[2];
    out[3] ^= dgst[3];
    out[4] ^= dgst[4];
    out[5] ^= dgst[5];
    out[6] ^= dgst[6];
    out[7] ^= dgst[7];
  }

  // macKey = bytes 16..31 of T1

  u32 mk[4];

  mk[0] = h32_from_64_S (out[2]);
  mk[1] = l32_from_64_S (out[2]);
  mk[2] = h32_from_64_S (out[3]);
  mk[3] = l32_from_64_S (out[3]);

  // verify HMAC-SHA256(macKey, salt16 || ct) against the stored hmac

  u32 cw[12];

  const u32 words = es->ct_len / 4;

  for (u32 i = 0; i < words; i++) cw[i] = es->ct[i];

  sha256_hmac_ctx_t h;

  sha256_hmac_init (&h, mk, 16);

  sha256_hmac_update (&h, bs, 16);

  sha256_hmac_update (&h, cw, es->ct_len);

  sha256_hmac_final (&h);

  const u32 r0 = h.opad.h[0];
  const u32 r1 = h.opad.h[1];
  const u32 r2 = h.opad.h[2];
  const u32 r3 = h.opad.h[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
