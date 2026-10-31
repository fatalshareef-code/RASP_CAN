#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define MASK64 UINT64_MAX
static uint64_t load64_le(const uint8_t *p){
    uint64_t x=0; for(int i=0;i<8;i++) x |= ((uint64_t)p[i]) << (8*i); return x;
}
static void store64_le(uint8_t *p,uint64_t x){ for(int i=0;i<8;i++) p[i]=(uint8_t)(x>>(8*i)); }
static uint64_t rotr64(uint64_t x,int n){ return (x>>n)|(x<<(64-n)); }
static void perm(uint64_t S[5], int rounds){
    for(int r=12-rounds;r<12;r++){
        S[2] ^= (uint64_t)(0xf0 - r*0x10 + r*0x1);
        S[0]^=S[4]; S[4]^=S[3]; S[2]^=S[1];
        uint64_t T[5]; for(int i=0;i<5;i++) T[i]=(~S[i]) & S[(i+1)%5];
        for(int i=0;i<5;i++) S[i]^=T[(i+1)%5];
        S[1]^=S[0]; S[0]^=S[4]; S[3]^=S[2]; S[2]=~S[2];
        S[0]^=rotr64(S[0],19)^rotr64(S[0],28);
        S[1]^=rotr64(S[1],61)^rotr64(S[1],39);
        S[2]^=rotr64(S[2],1)^rotr64(S[2],6);
        S[3]^=rotr64(S[3],10)^rotr64(S[3],17);
        S[4]^=rotr64(S[4],7)^rotr64(S[4],41);
    }
}
void ascon_cxof128_c(const uint8_t *msg,size_t mlen,const uint8_t *custom,size_t zlen,uint8_t *out,size_t outlen){
    uint8_t iv[8]={4,0,0xcc,0,0,8,0,0}; // version 4, b=12,a=12, taglen=0, rate=8
    uint64_t S[5]={load64_le(iv),0,0,0,0}; perm(S,12);
    uint8_t lenb[8]; store64_le(lenb,(uint64_t)zlen*8);
    S[0]^=load64_le(lenb); perm(S,12);
    size_t off=0;
    while(off+8<=zlen){ S[0]^=load64_le(custom+off); perm(S,12); off+=8; }
    uint8_t blk[8]={0}; size_t rem=zlen-off; if(rem) memcpy(blk,custom+off,rem); blk[rem]=0x01; S[0]^=load64_le(blk); perm(S,12);
    off=0;
    while(off+8<=mlen){ S[0]^=load64_le(msg+off); perm(S,12); off+=8; }
    memset(blk,0,8); rem=mlen-off; if(rem) memcpy(blk,msg+off,rem); blk[rem]=0x01; S[0]^=load64_le(blk); perm(S,12);
    size_t done=0; while(done<outlen){ uint8_t ob[8]; store64_le(ob,S[0]); size_t n=(outlen-done<8)?outlen-done:8; memcpy(out+done,ob,n); done+=n; perm(S,12); }
}
static void aead_init(uint64_t S[5],const uint8_t key[16],const uint8_t nonce[16]){
    uint8_t iv[8]={1,0,0x8c,0x80,0,16,0,0}; // taglen 128 little endian = 0x0080
    S[0]=load64_le(iv); S[1]=load64_le(key); S[2]=load64_le(key+8); S[3]=load64_le(nonce); S[4]=load64_le(nonce+8);
    perm(S,12); S[3]^=load64_le(key); S[4]^=load64_le(key+8);
}
static void aead_ad(uint64_t S[5],const uint8_t *ad,size_t adlen){
    if(adlen){
        size_t off=0; while(off+16<=adlen){ S[0]^=load64_le(ad+off); S[1]^=load64_le(ad+off+8); perm(S,8); off+=16; }
        uint8_t blk[16]={0}; size_t rem=adlen-off; if(rem) memcpy(blk,ad+off,rem); blk[rem]=0x01; S[0]^=load64_le(blk); S[1]^=load64_le(blk+8); perm(S,8);
    }
    S[4]^=((uint64_t)1<<63);
}
static void aead_encrypt(const uint8_t key[16],const uint8_t nonce[16],const uint8_t *ad,size_t adlen,const uint8_t *pt,size_t plen,uint8_t *ct,uint8_t tag[16]){
    uint64_t S[5]; aead_init(S,key,nonce); aead_ad(S,ad,adlen);
    size_t off=0;
    while(off+16<=plen){ S[0]^=load64_le(pt+off); S[1]^=load64_le(pt+off+8); store64_le(ct+off,S[0]); store64_le(ct+off+8,S[1]); perm(S,8); off+=16; }
    uint8_t blk[16]={0}; size_t rem=plen-off; if(rem) memcpy(blk,pt+off,rem); blk[rem]=0x01; S[0]^=load64_le(blk); S[1]^=load64_le(blk+8);
    uint8_t sb[16]; store64_le(sb,S[0]); store64_le(sb+8,S[1]); if(rem) memcpy(ct+off,sb,rem);
    S[2]^=load64_le(key); S[3]^=load64_le(key+8); perm(S,12); S[3]^=load64_le(key); S[4]^=load64_le(key+8); store64_le(tag,S[3]); store64_le(tag+8,S[4]);
}
static int aead_decrypt_verify_trunc(const uint8_t key[16],const uint8_t nonce[16],const uint8_t *ad,size_t adlen,const uint8_t *ct,size_t clen,const uint8_t *tag,size_t taglen,uint8_t *pt){
    uint64_t S[5]; aead_init(S,key,nonce); aead_ad(S,ad,adlen);
    size_t off=0;
    while(off+16<=clen){ uint64_t c0=load64_le(ct+off),c1=load64_le(ct+off+8); store64_le(pt+off,S[0]^c0); store64_le(pt+off+8,S[1]^c1); S[0]=c0;S[1]=c1;perm(S,8);off+=16; }
    size_t rem=clen-off; uint8_t cblk[16]={0}; if(rem) memcpy(cblk,ct+off,rem);
    uint8_t sblk[16]; store64_le(sblk,S[0]);store64_le(sblk+8,S[1]); for(size_t i=0;i<rem;i++) pt[off+i]=sblk[i]^cblk[i];
    uint8_t padx[16]={0},mask[16]; memset(mask,0xff,16); for(size_t i=0;i<rem;i++) mask[i]=0; padx[rem]=0x01;
    S[0]=(S[0]&load64_le(mask))^load64_le(cblk)^load64_le(padx); S[1]=(S[1]&load64_le(mask+8))^load64_le(cblk+8)^load64_le(padx+8);
    S[2]^=load64_le(key); S[3]^=load64_le(key+8); perm(S,12); S[3]^=load64_le(key); S[4]^=load64_le(key+8);
    uint8_t full[16];store64_le(full,S[3]);store64_le(full+8,S[4]);
    uint8_t diff=0; for(size_t i=0;i<taglen;i++) diff|=full[i]^tag[i]; return diff==0;
}
static void put16le(uint8_t *p,uint16_t x){p[0]=x&0xff;p[1]=x>>8;}
static void put32le(uint8_t *p,uint32_t x){for(int i=0;i<4;i++)p[i]=(x>>(8*i))&0xff;}
static void put64le(uint8_t *p,uint64_t x){for(int i=0;i<8;i++)p[i]=(x>>(8*i))&0xff;}

// Returns 1 iff sender encryption and receiver truncated-tag verification round-trip succeeds.
// out contains ciphertext followed by truncated tag (max 24 bytes), outlen receives length.
int rasp_protect_verify_c(const uint8_t state[16],uint16_t can_id,uint32_t epoch,uint64_t counter,uint8_t profile,uint8_t record_type,const uint8_t *pt,size_t plen,size_t taglen,uint8_t next_state[16],uint8_t *out,size_t *outlen){
    uint8_t ctx[16]; put16le(ctx,can_id);ctx[2]=0;ctx[3]=profile;put32le(ctx+4,epoch);put64le(ctx+8,counter);
    uint8_t msg[32];memcpy(msg,state,16);memcpy(msg+16,ctx,16);
    static const uint8_t ckey[]="RASP-CAN/KEY"; static const uint8_t cstep[]="RASP-CAN/STEP";
    uint8_t key[16]; ascon_cxof128_c(msg,32,ckey,sizeof(ckey)-1,key,16); ascon_cxof128_c(msg,32,cstep,sizeof(cstep)-1,next_state,16);
    uint8_t nonce[16];memcpy(nonce,ctx,16);
    uint8_t ad[19];put16le(ad,can_id);ad[2]=(uint8_t)(plen+taglen);ad[3]=record_type;ad[4]=profile;ad[5]=0;put32le(ad+6,epoch);put64le(ad+10,counter);ad[18]=(uint8_t)plen;
    uint8_t tag[16],dec[32]; aead_encrypt(key,nonce,ad,sizeof(ad),pt,plen,out,tag); memcpy(out+plen,tag,taglen);*outlen=plen+taglen;
    int ok=aead_decrypt_verify_trunc(key,nonce,ad,sizeof(ad),out,plen,out+plen,taglen,dec); if(!ok||memcmp(dec,pt,plen)!=0)return 0; return 1;
}
int rasp_checkpoint_verify_c(const uint8_t recovery_key[16],uint16_t can_id,uint32_t epoch,uint64_t counter,const uint8_t payload[8],uint8_t next_state[16],const uint8_t state[16],uint8_t out[24]){
    uint8_t nonce[16];put16le(nonce,can_id);nonce[2]=1;nonce[3]=64;put32le(nonce+4,epoch);put64le(nonce+8,counter);
    uint8_t pt[16];put32le(pt,epoch);put32le(pt+4,(uint32_t)counter);memcpy(pt+8,payload,8);
    uint8_t ad[18];put16le(ad,can_id);ad[2]=24;ad[3]=2;ad[4]=64;ad[5]=0;put32le(ad+6,epoch);put64le(ad+10,counter);
    uint8_t tag[16],dec[16];aead_encrypt(recovery_key,nonce,ad,sizeof(ad),pt,16,out,tag);memcpy(out+16,tag,8);
    int ok=aead_decrypt_verify_trunc(recovery_key,nonce,ad,sizeof(ad),out,16,out+16,8,dec);
    uint8_t msg[32];memcpy(msg,state,16);memcpy(msg+16,nonce,16);static const uint8_t cstep[]="RASP-CAN/STEP";ascon_cxof128_c(msg,32,cstep,sizeof(cstep)-1,next_state,16);
    return ok && memcmp(dec,pt,16)==0;
}
void ascon_aead128_encrypt_c(const uint8_t key[16],const uint8_t nonce[16],const uint8_t *ad,size_t adlen,const uint8_t *pt,size_t plen,uint8_t *out){uint8_t tag[16];aead_encrypt(key,nonce,ad,adlen,pt,plen,out,tag);memcpy(out+plen,tag,16);}
