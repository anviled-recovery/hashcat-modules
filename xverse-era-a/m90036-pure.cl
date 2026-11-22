/**
 * Author......: anviled.io (based on hashcat's m34000-pure.cl)
 * License.....: MIT
 *
 * Mode 90036 - Xverse Wallet (seedless)
 *
 * argon2id(password, utf8(passwordSalt-hex-string), t=3, m=65536, p=4, 16)
 * -> key = utf8(hex(passwordHash)) -> AES-256-GCM (iv 16 bytes)
 * -> era b: 32-byte sample must be [0-9a-f]{32} (bip39 entropy hex)
 * -> era c: sample starts with {"seedEncryptionKey":" + hex chars
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#include M2S(INCLUDE_PATH/inc_hash_argon2.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes-gcm.cl)
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

  u32 era;           // 0 = b (entropy hex), 1 = c (vault JSON)
  u32 salt_str[16];  // the 64 ascii chars of the passwordSalt hex string
  u32 iv_buf[4];     // 16-byte GCM iv
  u32 ct_buf[8];     // first 32 bytes of ciphertext

} merged_options_t;

KERNEL_FQ KERNEL_FA void m90036_init (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
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

  // the real argon2 salt lives in the esalt (the 64 ascii chars of the
  // passwordSalt hex string); salt_bufs carries a synthetic unique salt so
  // that same-install lines stay separate salts

  salt_t s;

  for (u32 i = 0; i < sizeof (salt_t) / 4; i++) ((PRIVATE_AS u32 *) &s)[i] = 0;

  for (u32 i = 0; i < 16; i++) s.salt_buf[i] = es->salt_str[i];

  s.salt_len = 64;

  argon2_init_gp (&pws[gid], &s, &argon2_options, argon2_block);
}

KERNEL_FQ KERNEL_FA void m90036_loop (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
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

KERNEL_FQ KERNEL_FA void m90036_comp (KERN_ATTR_TMPS_ESALT (argon2_tmp_t, merged_options_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

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

  const argon2_options_t argon2_options = esalt_bufs[DIGESTS_OFFSET_HOST].argon2_options;

  GLOBAL_AS argon2_block_t *argon2_block = get_argon2_block (&argon2_options, V, gd4);

  GLOBAL_AS const merged_options_t *es = &esalt_bufs[DIGESTS_OFFSET_HOST];

  // 16-byte passwordHash, LE-packed words (blake2b convention)

  u32 out[16];

  argon2_final (argon2_block, &argon2_options, out);

  // the AES-256 key is the UTF-8 of the lowercase hex of those 16 bytes:
  // 32 ascii chars, packed big-endian into key words

  u32 ukey[8];

  for (u32 i = 0; i < 8; i++)
  {
    u32 w4 = 0;

    for (u32 j = 0; j < 4; j++)
    {
      const u32 cidx = i * 4 + j;                                   // hex char index
      const u32 tbyte = (out[cidx / 8] >> (((cidx / 2) & 3) * 8)) & 0xff;

      u32 nib = (cidx & 1) ? (tbyte & 0xf) : (tbyte >> 4);

      nib += (nib < 10) ? 0x30 : 0x57;                              // 0-9, a-f

      w4 |= nib << ((3 - j) * 8);
    }

    ukey[i] = w4;
  }

  u32 key_len = 32 * 8;

  u32 key[60] = { 0 };
  u32 subKey[4] = { 0 };

  AES_GCM_Init (ukey, key_len, key, subKey, s_te0, s_te1, s_te2, s_te3, s_te4);

  // iv (16 bytes -> J0 = GHASH_H(pad16(iv) || 0^64 || [len(iv)]64))

  u32 iv[4];

  iv[0] = es->iv_buf[0];
  iv[1] = es->iv_buf[1];
  iv[2] = es->iv_buf[2];
  iv[3] = es->iv_buf[3];

  u32 J0[4] = { 0 };

  AES_GCM_Prepare_J0 (iv, 16, subKey, J0);

  u32 ct[8];

  ct[0] = es->ct_buf[0];
  ct[1] = es->ct_buf[1];
  ct[2] = es->ct_buf[2];
  ct[3] = es->ct_buf[3];
  ct[4] = es->ct_buf[4];
  ct[5] = es->ct_buf[5];
  ct[6] = es->ct_buf[6];
  ct[7] = es->ct_buf[7];

  u32 pt[8] = { 0 };

  AES_GCM_decrypt (key, key_len, J0, ct, 32, pt, s_te0, s_te1, s_te2, s_te3, s_te4);

  if (es->era == 1)
  {
    // era c: plaintext is {"seedEncryptionKey":"<hex>",...}

    if (pt[0] != 0x7b227365) return;   // {"se
    if (pt[1] != 0x6564456e) return;   // edEn
    if (pt[2] != 0x63727970) return;   // cryp
    if (pt[3] != 0x74696f6e) return;   // tion
    if (pt[4] != 0x4b657922) return;   // Key"
    if ((pt[5] >> 16) != 0x3a22) return; // :"

    // bytes 22..31 must be hex chars

    for (u32 i = 22; i < 32; i++)
    {
      const u32 c = (pt[i / 4] >> ((3 - (i & 3)) * 8)) & 0xff;

      if ((c >= 0x30) && (c <= 0x39)) continue;
      if ((c >= 0x61) && (c <= 0x66)) continue;

      return;
    }
  }
  else
  {
    // era b: plaintext is the bip39 entropy as 32 lowercase hex chars

    for (u32 i = 0; i < 32; i++)
    {
      const u32 c = (pt[i / 4] >> ((3 - (i & 3)) * 8)) & 0xff;

      if ((c >= 0x30) && (c <= 0x39)) continue;
      if ((c >= 0x61) && (c <= 0x66)) continue;

      return;
    }
  }

  const u32 r0 = ct[0];
  const u32 r1 = ct[1];
  const u32 r2 = ct[2];
  const u32 r3 = ct[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
