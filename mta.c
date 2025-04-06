#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32) || defined(_WIN64)
  #include <windows.h>
  #include <wincrypt.h>
  static int get_random_bytes(uint8_t *buf, size_t len) {
      HCRYPTPROV hProv = 0;
      if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
          return 0; // fail
      }
      if (!CryptGenRandom(hProv, (DWORD)len, buf)) {
          CryptReleaseContext(hProv, 0);
          return 0;
      }
      CryptReleaseContext(hProv, 0);
      return 1; // success
  }
#else
  #include <unistd.h>
  static int get_random_bytes(uint8_t *buf, size_t len) {
      FILE *fp = fopen("/dev/urandom", "rb");
      if (!fp) return 0;
      size_t n = fread(buf, 1, len, fp);
      fclose(fp);
      return (n == len);
  }
#endif


typedef struct {
    uint8_t be[32];
} bignum256;

// secp256k1 prime p = 2^256 - 2^32 - 977 in big-endian
static const uint8_t SECP256K1_P[32] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
    0xff,0xff,0xfc,0x2f,0x00,0x00,0x00,0x00
};



static void bn_copy(const bignum256 *src, bignum256 *dst) {
    memcpy(dst->be, src->be, 32);
}

// read 32 bytes (big-endian) => bignum
static void bn_read_be(const uint8_t in[32], bignum256 *x) {
    memcpy(x->be, in, 32);
}

// write bignum => out[32] big-endian
static void bn_write_be(const bignum256 *x, uint8_t out[32]) {
    memcpy(out, x->be, 32);
}

// compare x,y => 0 if eq, <0 if x<y, >0 if x>y
static int bn_cmp(const bignum256 *x, const bignum256 *y) {
    return memcmp(x->be, y->be, 32);
}

// while x >= p: x -= p
static void bn_mod(bignum256 *x, const bignum256 *p) {
    while (bn_cmp(x, p) >= 0) {
        int carry = 0;
        for (int i=31; i>=0; i--) {
            int diff = x->be[i] - p->be[i] - carry;
            if (diff < 0) {
                diff += 256;
                carry = 1;
            } else {
                carry = 0;
            }
            x->be[i] = (uint8_t)diff;
        }
    }
}

// x = x + y
static void bn_add(bignum256 *x, const bignum256 *y) {
    int carry=0;
    for (int i=31; i>=0; i--) {
        unsigned sum = x->be[i] + y->be[i] + carry;
        x->be[i] = sum & 0xff;
        carry = sum >> 8;
    }
}

// x = x - y
static void bn_sub(bignum256 *x, const bignum256 *y) {
    int carry=0;
    for (int i=31; i>=0; i--) {
        int diff = x->be[i] - y->be[i] - carry;
        if (diff<0) {
            diff += 256;
            carry=1;
        } else {
            carry=0;
        }
        x->be[i] = diff & 0xff;
    }
}

// x <<= 1 (x *=2)
static void bn_lshift(bignum256 *x) {
    int carry=0;
    for (int i=31; i>=0; i--) {
        int val = (x->be[i]<<1) | carry;
        x->be[i] = val & 0xff;
        carry = (val>>8)&1;
    }
}


static void bn_mul(const bignum256 *x, const bignum256 *y, bignum256 *res) {
    // convert x,y to little-endian
    uint8_t lx[32], ly[32];
    for (int i=0; i<32; i++){
        lx[i] = x->be[31-i];
        ly[i] = y->be[31-i];
    }
    // 64 bytes of partial sums
    uint16_t tmp[64];
    memset(tmp, 0, sizeof(tmp));

    for (int i=0; i<32; i++){
        for (int j=0; j<32; j++){
            unsigned prod = lx[i]*ly[j];
            tmp[i+j] += prod;
            tmp[i+j+1] += (tmp[i+j] >>8);
            tmp[i+j] &=0xff;
        }
    }

    // lower 256 bits => out_le
    uint8_t out_le[32];
    for (int i=0; i<32; i++){
        out_le[i] = tmp[i] &0xff;
    }
    // convert out_le => big-endian
    for (int i=0; i<32; i++){
        res->be[i] = out_le[31-i];
    }
}


//  For brevity, we define a small, straightforward SHA-256. 

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[64];
} toy_sha256_ctx;

#define ROR32(a,b) (((a) >> (b)) | ((a) << (32-(b))))

static uint32_t toy_sha256_k[64] = {
  0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
  0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
  0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
  0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
  0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
  0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
  0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
  0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2
};

static void toy_sha256_transform(toy_sha256_ctx *ctx, const uint8_t data[64]) {
    uint32_t m[64], a,b,c,d,e,f,g,h;

    for (int i=0; i<16; i++) {
        m[i] = (data[4*i]<<24) | (data[4*i+1]<<16) | (data[4*i+2]<<8) | (data[4*i+3]);
    }
    for (int i=16; i<64; i++) {
        uint32_t s0 = ROR32(m[i-15],7) ^ ROR32(m[i-15],18) ^ (m[i-15]>>3);
        uint32_t s1 = ROR32(m[i-2],17) ^ ROR32(m[i-2],19) ^ (m[i-2]>>10);
        m[i] = m[i-16]+ s0 + m[i-7] + s1;
    }
    a= ctx->state[0];
    b= ctx->state[1];
    c= ctx->state[2];
    d= ctx->state[3];
    e= ctx->state[4];
    f= ctx->state[5];
    g= ctx->state[6];
    h= ctx->state[7];

    for(int i=0;i<64;i++){
        uint32_t S1= ROR32(e,6)^ROR32(e,11)^ROR32(e,25);
        uint32_t ch= (e&f) ^ ((~e)&g);
        uint32_t temp1 = h + S1 + ch + toy_sha256_k[i] + m[i];
        uint32_t S0= ROR32(a,2)^ROR32(a,13)^ROR32(a,22);
        uint32_t maj=(a&b)^(a&c)^(b&c);
        uint32_t temp2= S0+ maj;
        h=g;
        g=f;
        f=e;
        e=d+ temp1;
        d=c;
        c=b;
        b=a;
        a=temp1+ temp2;
    }

    ctx->state[0]+=a;
    ctx->state[1]+=b;
    ctx->state[2]+=c;
    ctx->state[3]+=d;
    ctx->state[4]+=e;
    ctx->state[5]+=f;
    ctx->state[6]+=g;
    ctx->state[7]+=h;
}

static void toy_sha256_init(toy_sha256_ctx* ctx){
    ctx->state[0]= 0x6A09E667;
    ctx->state[1]= 0xBB67AE85;
    ctx->state[2]= 0x3C6EF372;
    ctx->state[3]= 0xA54FF53A;
    ctx->state[4]= 0x510E527F;
    ctx->state[5]= 0x9B05688C;
    ctx->state[6]= 0x1F83D9AB;
    ctx->state[7]= 0x5BE0CD19;
    ctx->bitlen=0;
    memset(ctx->buffer,0,64);
}

static void toy_sha256_update(toy_sha256_ctx* ctx, const uint8_t* data, size_t len){
    for(size_t i=0; i<len; i++){
        ctx->buffer[ (ctx->bitlen>>3) & 63 ]= data[i];
        ctx->bitlen += 8;
        if(((ctx->bitlen>>3) & 63)==0){
            toy_sha256_transform(ctx, ctx->buffer);
        }
    }
}

static void toy_sha256_final(toy_sha256_ctx* ctx, uint8_t out[32]){
    // total bits => pad
    uint64_t bitlen_be = ((uint64_t)ctx->bitlen);
    // append 0x80
    size_t i= (ctx->bitlen>>3) & 63;
    ctx->buffer[i++]= 0x80;
    if(i>56){
        // fill zeros
        while(i<64) ctx->buffer[i++]=0x00;
        toy_sha256_transform(ctx, ctx->buffer);
        i=0;
    }
    while(i<56) ctx->buffer[i++]=0x00;
    // length in big-endian
    for(int j=7;j>=0;j--){
        ctx->buffer[i++]= (uint8_t)(bitlen_be>>(j*8));
    }
    toy_sha256_transform(ctx, ctx->buffer);
    for(int j=0;j<8;j++){
        out[4*j+0]= (uint8_t)(ctx->state[j]>>24);
        out[4*j+1]= (uint8_t)(ctx->state[j]>>16);
        out[4*j+2]= (uint8_t)(ctx->state[j]>>8);
        out[4*j+3]= (uint8_t)(ctx->state[j]);
    }
}

static void xor_key(uint8_t *data, size_t len, const uint8_t *key32){
    for (size_t i=0;i<len;i++){
        data[i]^= key32[i%32];
    }
}

//  * Final main: correlated MTA demonstration
//  *
//  * Steps:
//  *   1) random a,b in [0..p-1]
//  *   2) product= a*b mod p
//  *   3) pick random r => c=r, d=(product-r) mod p
//  *   4) ephemeral encryption: ephemeral_key(32), hashed via toy_sha256 => key
//  *      c_enc= c XOR key
//  *      d_enc= d XOR key
//  *   5) verify => decrypt c_enc,d_enc => c,d => c+d= product
//  *
int main(void){
    // read prime p
    bignum256 bn_p;
    bn_read_be(SECP256K1_P, &bn_p);

    //  Step 1: random a,b
    // get random 32 bytes, reduce mod p => a, likewise => b
    uint8_t a_be[32], b_be[32];
    if(!get_random_bytes(a_be,32) || !get_random_bytes(b_be,32)){
        fprintf(stderr,"RNG fail.\n");
        return 1;
    }
    bignum256 bn_a, bn_b;
    bn_read_be(a_be, &bn_a);
    bn_mod(&bn_a, &bn_p);
    bn_read_be(b_be, &bn_b);
    bn_mod(&bn_b, &bn_p);
    // rewrite the final a,b
    bn_write_be(&bn_a, a_be);
    bn_write_be(&bn_b, b_be);

    //  Step 2: product
    bignum256 bn_prod;
    bn_mul(&bn_a,&bn_b, &bn_prod);
    bn_mod(&bn_prod,&bn_p);

    //  Step 3: pick random r => c=r, d=(prod-r) mod p
    uint8_t r_be[32];
    if(!get_random_bytes(r_be,32)){
        fprintf(stderr,"RNG fail.\n");
        return 1;
    }
    bignum256 bn_r;
    bn_read_be(r_be, &bn_r);
    bn_mod(&bn_r,&bn_p);

    // c= r
    bignum256 bn_c;
    bn_copy(&bn_r,&bn_c);

    // d= product - r
    bignum256 bn_d;
    bn_copy(&bn_prod,&bn_d);
    bn_sub(&bn_d,&bn_r);
    bn_mod(&bn_d,&bn_p);

    //  Step 4: ephemeral encryption
    uint8_t ephemeral_key[32];
    if(!get_random_bytes(ephemeral_key,32)){
        fprintf(stderr,"Ephemeral RNG fail.\n");
        return 1;
    }
    // hashed_key= toy_sha256(ephemeral_key)
    uint8_t hashed_key[32];
    {
        // run the toy sha
        toy_sha256_ctx ctx;
        toy_sha256_init(&ctx);
        toy_sha256_update(&ctx, ephemeral_key, 32);
        toy_sha256_final(&ctx, hashed_key);
    }

    // c_enc= c XOR hashed_key,  d_enc= d XOR hashed_key
    uint8_t c_enc[32], d_enc[32];
    bn_write_be(&bn_c, c_enc);
    bn_write_be(&bn_d, d_enc);
    xor_key(c_enc,32, hashed_key);
    xor_key(d_enc,32, hashed_key);

    // print everything
    printf("a = "); for(int i=0;i<32;i++) printf("%02x", a_be[i]); printf("\n");
    printf("b = "); for(int i=0;i<32;i++) printf("%02x", b_be[i]); printf("\n");
    printf("Encrypted c = "); for(int i=0;i<32;i++) printf("%02x", c_enc[i]); printf("\n");
    printf("Encrypted d = "); for(int i=0;i<32;i++) printf("%02x", d_enc[i]); printf("\n");

    //  Step 5: verify
    // decrypt
    xor_key(c_enc,32,hashed_key);
    xor_key(d_enc,32,hashed_key);
    bignum256 check_c, check_d;
    bn_read_be(c_enc,&check_c);
    bn_read_be(d_enc,&check_d);

    // sum= c + d mod p
    bignum256 sum;
    bn_copy(&check_c,&sum);
    bn_add(&sum,&check_d);
    bn_mod(&sum,&bn_p);

    // compare sum vs bn_prod
    if(bn_cmp(&sum,&bn_prod)==0){
        printf("MtA success: c+d == a*b (mod p)\n");
    } else {
        printf("MtA FAIL!\n");
    }

    return 0;
}
