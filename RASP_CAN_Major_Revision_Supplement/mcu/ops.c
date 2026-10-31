#include <stdint.h>
#include <string.h>
#include "ascon_rasp.c"
/* codec pieces copied verbatim from adversarial_rasp_validate.c */
enum {M_RAW=0,M_HOLD=1,M_D1=2,M_D2=3,M_XOR=4};
static uint64_t choose_u64(uint64_t n, uint64_t k){if(k>n)return 0;if(k>n-k)k=n-k;uint64_t r=1;for(uint64_t i=1;i<=k;i++)r=r*(n-k+i)/i;return r;}
static int rbits(int z){uint64_t c=choose_u64(16,z);int b=0;uint64_t v=1;while(v<c){v<<=1;b++;}return b;}
static int codec_bits(int z){return 10+rbits(z)+4*z;}
static uint64_t rank_subset(const int *pos,int z){uint64_t rank=0;int prev=-1;for(int i=0;i<z;i++){for(int v=prev+1;v<pos[i];v++)rank+=choose_u64(16-v-1,z-i-1);prev=pos[i];}return rank;}
static int unrank_subset(int z,uint64_t rank,int *pos){int prev=-1;for(int i=0;i<z;i++){int found=0;for(int v=prev+1;v<16;v++){uint64_t c=choose_u64(16-v-1,z-i-1);if(rank<c){pos[i]=v;prev=v;found=1;break;}rank-=c;}if(!found)return 0;}return rank==0;}
static void to_nibbles(const uint8_t b[8],uint8_t n[16]){for(int i=0;i<8;i++){n[2*i]=b[i]>>4;n[2*i+1]=b[i]&15;}}
static void from_nibbles(const uint8_t n[16],uint8_t b[8]){for(int i=0;i<8;i++)b[i]=(n[2*i]<<4)|n[2*i+1];}
static void residual(const uint8_t cur[16],const uint8_t prev[16],const uint8_t prev2[16],int mode,uint8_t r[16]){for(int i=0;i<16;i++){if(mode==M_HOLD||mode==M_D1)r[i]=(cur[i]-prev[i])&15;else if(mode==M_D2)r[i]=(cur[i]-(2*prev[i]-prev2[i]))&15;else r[i]=cur[i]^prev[i];}}
static void inverse(const uint8_t r[16],const uint8_t prev[16],const uint8_t prev2[16],int mode,uint8_t cur[16]){for(int i=0;i<16;i++){if(mode==M_HOLD||mode==M_D1)cur[i]=(prev[i]+r[i])&15;else if(mode==M_D2)cur[i]=(2*prev[i]-prev2[i]+r[i])&15;else cur[i]=prev[i]^r[i];}}
typedef struct{int valid,L,z,pri,mode;uint8_t r[16];} Candidate;
typedef struct{int has_prev,has_prev2;uint8_t prev[8],prev2[8];} Hist;
static Candidate choose_mode(const uint8_t payload[8],const Hist *ctx){Candidate best={0,999,0,0,0,{0}};uint8_t cur[16],p[16],p2[16],r[16];to_nibbles(payload,cur);if(ctx->has_prev)to_nibbles(ctx->prev,p);if(ctx->has_prev2)to_nibbles(ctx->prev2,p2);const int modes[4]={M_HOLD,M_D2,M_XOR,M_D1};for(int pri=0;pri<4;pri++){int m=modes[pri];if(!ctx->has_prev)continue;if(m==M_D2&&!ctx->has_prev2)continue;residual(cur,p,p2,m,r);int z=0;for(int i=0;i<16;i++)if(r[i])z++;int L=codec_bits(z);if(!best.valid||L<best.L||(L==best.L&&z<best.z)||(L==best.L&&z==best.z&&pri<best.pri)){best.valid=1;best.L=L;best.z=z;best.pri=pri;best.mode=m;memcpy(best.r,r,16);}}return best;}
static int pack_normal(const Candidate *c,uint8_t body[4],int *bodylen){int pos[16],z=0;uint8_t vals[16];for(int i=0;i<16;i++)if(c->r[i]){pos[z]=i;vals[z]=c->r[i];z++;}int rb=rbits(z),nb=10+rb+4*z,nbytes=(nb+7)/8;if(nbytes>4)return 0;uint64_t rank=rank_subset(pos,z);uint64_t x=((uint64_t)c->mode<<5)|z;if(rb)x=(x<<rb)|rank;for(int i=0;i<z;i++)x=(x<<4)|vals[i];x<<=(nbytes*8-nb);for(int i=0;i<nbytes;i++)body[i]=(x>>(8*(nbytes-1-i)))&0xff;*bodylen=nbytes;return 1;}
static int decode_normal(const uint8_t *body,int bodylen,const Hist *ctx,uint8_t out[8]){int total=bodylen*8;uint64_t x=0;for(int i=0;i<bodylen;i++)x=(x<<8)|body[i];uint64_t header=x>>(total-10);int typ=(header>>8)&3,mode=(header>>5)&7,z=header&31;if(typ!=0||z>16)return 0;int rb=rbits(z);int cursor=total-10;uint64_t rank=rb?((x>>(cursor-rb))&(((uint64_t)1<<rb)-1)):0;cursor-=rb;int pos[16];if(!unrank_subset(z,rank,pos))return 0;uint8_t r[16]={0};for(int i=0;i<z;i++){cursor-=4;r[pos[i]]=(x>>cursor)&15;}if(cursor>0&&(x&(((uint64_t)1<<cursor)-1)))return 0;uint8_t p[16],p2[16],cur[16];to_nibbles(ctx->prev,p);if(ctx->has_prev2)to_nibbles(ctx->prev2,p2);inverse(r,p,p2,mode,cur);from_nibbles(cur,out);return 1;}

/* split sender / receiver, same KDF/nonce/AD layout as rasp_protect_verify_c */
static void mkctx(uint8_t ctx[16],uint16_t id,uint32_t e,uint64_t c){put16le(ctx,id);ctx[2]=0;ctx[3]=32;put32le(ctx+4,e);put64le(ctx+8,c);}
static void mkad(uint8_t ad[19],uint16_t id,uint32_t e,uint64_t c,size_t plen,size_t tl,int rt){put16le(ad,id);ad[2]=(uint8_t)(plen+tl);ad[3]=rt;ad[4]=32;ad[5]=0;put32le(ad+6,e);put64le(ad+10,c);ad[18]=(uint8_t)plen;}
static const uint8_t CK[]="RASP-CAN/KEY",CS[]="RASP-CAN/STEP";
static void derive(const uint8_t S[16],const uint8_t ctx[16],uint8_t K[16],uint8_t N[16]){uint8_t m[32];memcpy(m,S,16);memcpy(m+16,ctx,16);ascon_cxof128_c(m,32,CK,12,K,16);ascon_cxof128_c(m,32,CS,13,N,16);}
int send_rec(uint8_t S[16],uint16_t id,uint32_t e,uint64_t c,const uint8_t*pt,size_t plen,size_t tl,int rt,uint8_t*out){uint8_t ctx[16],K[16],NS[16],ad[19],tag[16];mkctx(ctx,id,e,c);derive(S,ctx,K,NS);mkad(ad,id,e,c,plen,tl,rt);aead_encrypt(K,ctx,ad,19,pt,plen,out,tag);memcpy(out+plen,tag,tl);memcpy(S,NS,16);memset(K,0,16);return 0;}
int recv_try(const uint8_t S[16],uint16_t id,uint32_t e,uint64_t c,const uint8_t*in,size_t plen,size_t tl,int rt,uint8_t*pt,uint8_t NS[16]){uint8_t ctx[16],K[16],ad[19];mkctx(ctx,id,e,c);derive(S,ctx,K,NS);mkad(ad,id,e,c,plen,tl,rt);int ok=aead_decrypt_verify_trunc(K,ctx,ad,19,in,plen,in+plen,tl,pt);memset(K,0,16);return ok;}

volatile uint32_t sink;
static uint8_t S0[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
static uint8_t KR[16]={9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9};
int run_op(int op){
  Hist h={1,1,{0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80},{0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80}};
  uint8_t pay[8]={0x10,0x20,0x31,0x40,0x50,0x60,0x72,0x80};
  uint8_t S[16],R[16],out[32],pt[32],NS[16],body[4];int bl;memcpy(S,S0,16);memcpy(R,S0,16);
  switch(op){
  case 0: return 0; /* empty baseline */
  case 1: { Candidate c=choose_mode(pay,&h); pack_normal(&c,body,&bl); sink=bl; return 0;} /* codec encode */
  case 2: { Candidate c=choose_mode(pay,&h); pack_normal(&c,body,&bl); send_rec(S,0x123,1,7,body,bl,4,0,out); sink=out[0]; return 0;} /* full N32 sender */
  case 3: { Candidate c=choose_mode(pay,&h); pack_normal(&c,body,&bl); send_rec(S,0x123,1,7,body,bl,4,0,out);
            /* receiver, correct counter first candidate */
            int ok=recv_try(R,0x123,1,7,out,bl,4,0,pt,NS); uint8_t d[8]; ok&=decode_normal(pt,bl,&h,d); sink=ok; return 0;} /* sender+receiver: subtract op2 */
  case 4: { send_rec(S,0x123,1,7,pay,8,8,1,out); sink=out[0]; return 0;} /* E64 sender */
  case 5: { send_rec(S,0x123,1,7,pay,8,8,1,out); int ok=recv_try(R,0x123,1,7,out,8,8,1,pt,NS); sink=ok; return 0;} /* E64 send+recv */
  case 6: { uint8_t o[24]; rasp_checkpoint_verify_c(KR,0x123,1,7,pay,NS,S,o); sink=o[0]; return 0;} /* CHK64 enc+verify+step */
  case 7: { Candidate c=choose_mode(pay,&h); pack_normal(&c,body,&bl); send_rec(S,0x123,1,7,body,bl,4,0,out); out[bl]^=1; /* corrupt: receiver tries W=4 all fail */
            uint8_t T[16];memcpy(T,R,16);int ok=0;for(uint64_t c2=4;c2<8;c2++){ok|=recv_try(T,0x123,1,c2,out,bl,4,0,pt,NS);memcpy(T,NS,16);} sink=ok; return 0;} /* worst-case 4 failed candidates + send */
  case 8: { uint8_t K[16],N[16],ctx[16];mkctx(ctx,1,1,1);derive(S,ctx,K,N);sink=K[0];return 0;} /* one ratchet step: 2 CXOF */
  case 9: { uint8_t ctx[16],ad[19],tag[16];mkctx(ctx,1,1,1);mkad(ad,1,1,1,4,4,0);aead_encrypt(S,ctx,ad,19,pay,4,out,tag);sink=tag[0];return 0;} /* one AEAD enc 4B */
  case 10: { uint8_t o[24]={0},n2[16],d[16],ad[18]={0}; int ok=aead_decrypt_verify_trunc(KR,n2,ad,18,o,16,o+16,8,d); sink=ok; return 0;} /* forged CHK64: one AEAD verify, rejected */
  case 11: { uint8_t in[8]={0}; int ok=recv_try(R,0x123,1,7,in,4,4,0,pt,NS); sink=ok; return 0;} /* one failed N32 candidate */
  }
  return 0;
}
