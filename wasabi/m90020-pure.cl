/**
 * Author......: anviled.io (based on hashcat's m27700-pure.cl)
 * License.....: MIT
 *
 * Mode 90020 - Wasabi Wallet (BIP-0038 non-EC-multiplied secret)
 *
 * scrypt(password, addresshash, N=16384, r=8, p=8, dkLen=64)
 * -> AES-256-ECB-decrypt the two halves (key = derivedhalf2)
 * -> XOR with derivedhalf1 -> 32-byte private key
 * -> secp256k1 (point_mul by G) -> compressed pubkey
 * -> SHA256 -> RIPEMD160 -> Base58Check(0x00) address
 * -> addresshash == double-SHA256(address)[0:4]
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#include M2S(INCLUDE_PATH/inc_hash_ripemd160.cl)
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#include M2S(INCLUDE_PATH/inc_bitcoin_address.cl)
#include M2S(INCLUDE_PATH/inc_hash_base58.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct wasabi_esalt
{
  u32 flagbyte;
  u32 addrhash;      // 4-byte BIP38 address hash (= scrypt salt), BE u32
  u32 ct[8];         // 32 bytes of encrypted halves

} wasabi_esalt_t;

DECLSPEC void sha256_u32 (PRIVATE_AS const u32 *in, const int in_len, PRIVATE_AS u32 out[8])
{
  sha256_ctx_t ctx;

  sha256_init   (&ctx);
  sha256_update (&ctx, in, in_len);
  sha256_final  (&ctx);

  out[0] = ctx.h[0];
  out[1] = ctx.h[1];
  out[2] = ctx.h[2];
  out[3] = ctx.h[3];
  out[4] = ctx.h[4];
  out[5] = ctx.h[5];
  out[6] = ctx.h[6];
  out[7] = ctx.h[7];
}

KERNEL_FQ KERNEL_FA void m90020_init (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, wasabi_esalt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 w[128] = { 0 };

  for (u32 i = 0; i < 16; i++) w[i] = pws[gid].i[i];

  const int w_len = pws[gid].pw_len;

  u32 s[16] = { 0 };

  s[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].addrhash);

  scrypt_pbkdf2_ppg (w, w_len, s, 4, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m90020_loop_prepare (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, wasabi_esalt_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_init_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE);
}

KERNEL_FQ KERNEL_FA void m90020_loop (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, wasabi_esalt_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 bid = get_group_id (0);

  scrypt_smix_loop_kernel (tmps[0].out, sizeof (tmps[0]), d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, bid, GID_CNT, SALT_REPEAT, MODULE_TUNE, LOOP_CNT);
}

KERNEL_FQ KERNEL_FA void m90020_comp (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, wasabi_esalt_t))
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

  /**
   * raw password words
   */

  u32 w[128] = { 0 };

  for (u32 i = 0; i < 16; i++) w[i] = pws[gid].i[i];

  const int w_len = pws[gid].pw_len;

  /**
   * final PBKDF2 (dkLen = 64): out[0..7] = derivedhalf1, out[8..15] = derivedhalf2
   */

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  u32 out[16];

  scrypt_pbkdf2_pgp (w, w_len, tmps[gid].in, SCRYPT_SZ, out, 64);

  /**
   * AES-256-ECB decrypt both halves with derivedhalf2, XOR derivedhalf1
   */

  GLOBAL_AS const wasabi_esalt_t *es = &esalt_bufs[DIGESTS_OFFSET_HOST];

  u32 aes_key[8];

  for (u32 i = 0; i < 8; i++) aes_key[i] = hc_swap32_S (out[8 + i]);

  u32 ks[60];

  AES256_set_decrypt_key (ks, aes_key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 ct0[4];
  u32 ct1[4];

  ct0[0] = es->ct[0];
  ct0[1] = es->ct[1];
  ct0[2] = es->ct[2];
  ct0[3] = es->ct[3];
  ct1[0] = es->ct[4];
  ct1[1] = es->ct[5];
  ct1[2] = es->ct[6];
  ct1[3] = es->ct[7];

  u32 dec0[4];
  u32 dec1[4];

  aes256_decrypt (ks, ct0, dec0, s_td0, s_td1, s_td2, s_td3, s_td4);
  aes256_decrypt (ks, ct1, dec1, s_td0, s_td1, s_td2, s_td3, s_td4);

  u32 privkey[8];

  privkey[0] = dec0[0] ^ out[0];
  privkey[1] = dec0[1] ^ out[1];
  privkey[2] = dec0[2] ^ out[2];
  privkey[3] = dec0[3] ^ out[3];
  privkey[4] = dec1[0] ^ out[4];
  privkey[5] = dec1[1] ^ out[5];
  privkey[6] = dec1[2] ^ out[6];
  privkey[7] = dec1[3] ^ out[7];

  // point_mul_xy wants the scalar little-endian-limb (k[0] = lowest limb):
  // reverse the word order and byte-swap each word

  for (u32 i = 0; i < 4; i++)
  {
    const u32 t = hc_swap32_S (privkey[i]);
    privkey[i] = hc_swap32_S (privkey[7 - i]);
    privkey[7 - i] = t;
  }

  /**
   * secp256k1: pubkey = privkey * G -> hash160 (compressed)
   */

  secp256k1_t preG;

  set_precomputed_basepoint_g (&preG);

  u32 x[8];
  u32 y[8];

  point_mul_xy (x, y, privkey, &preG);

  u32 h160[5];

  hash160_pubkey_compressed (h160, x, y);

  /**
   * Base58Check address (0x00 || hash160 || checksum)
   */

  u8 addr[40];

  u32 addr_len = sizeof (addr);

  if (b58check_enc (addr, &addr_len, 0x00, (PRIVATE_AS const u8 *) h160, 20) == false) return;

  /**
   * addresshash check: dbl-SHA256(ascii address)[0:4] == esalt addrhash
   */

  u32 addr_w[12] = { 0 };

  for (u32 i = 0; i < addr_len; i++)
  {
    addr_w[i / 4] |= ((u32) addr[i]) << (24 - ((i & 3) * 8));
  }

  u32 ahash1[8];
  u32 ahash2[8];

  sha256_u32 (addr_w, addr_len - 1, ahash1);
  sha256_u32 (ahash1, 32, ahash2);

  const u32 r0 = ahash2[0];
  const u32 r1 = 0;
  const u32 r2 = 0;
  const u32 r3 = 0;

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
