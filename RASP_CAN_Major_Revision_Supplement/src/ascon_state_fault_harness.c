#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ascon_rasp.c"

static uint64_t rngs=0x6a09e667f3bcc909ULL;
static uint64_t rng64(void){rngs^=rngs<<13; rngs^=rngs>>7; rngs^=rngs<<17; return rngs;}
static void randbytes(uint8_t*x,size_t n){for(size_t i=0;i<n;i++)x[i]=(uint8_t)rng64();}
static void u16(uint8_t*p,uint16_t x){p[0]=x;p[1]=x>>8;}
static void u32(uint8_t*p,uint32_t x){for(int i=0;i<4;i++)p[i]=x>>(8*i);}
static void u64(uint8_t*p,uint64_t x){for(int i=0;i<8;i++)p[i]=x>>(8*i);}

typedef struct{uint8_t E[16],S[16],KR[16];uint32_t epoch;uint64_t ctr;uint64_t outstanding;int has_outstanding;} Node;
typedef struct{uint32_t epoch;uint64_t ctr;uint8_t ct[8],tag[8];size_t len;} Rec;
typedef struct{uint32_t olde,newe;uint64_t nR,nS;uint8_t tag[8];} SyncResp;

static void traffic_init(const uint8_t E[16],uint16_t id,uint32_t e,uint8_t S[16]){
 uint8_t m[22];memcpy(m,E,16);u16(m+16,id);u32(m+18,e);const uint8_t c[]="RASP-CAN/EPOCH-TRAFFIC";ascon_cxof128_c(m,sizeof(m),c,sizeof(c)-1,S,16);
}
static void frame_derive(const uint8_t S[16],uint16_t id,uint32_t e,uint64_t ctr,uint8_t key[16],uint8_t NS[16]){
 uint8_t ctx[16]={0};u16(ctx,id);ctx[2]=0;ctx[3]=64;u32(ctx+4,e);u64(ctx+8,ctr);uint8_t m[32];memcpy(m,S,16);memcpy(m+16,ctx,16);
 const uint8_t ck[]="RASP-CAN/KEY",cs[]="RASP-CAN/STEP";ascon_cxof128_c(m,32,ck,sizeof(ck)-1,key,16);ascon_cxof128_c(m,32,cs,sizeof(cs)-1,NS,16);
}
static void make_rec(Node*s,uint16_t id,const uint8_t*pt,size_t n,Rec*r){
 uint8_t key[16],ns[16],nonce[16]={0},ad[19]={0},tag[16];r->epoch=s->epoch;r->ctr=s->ctr;r->len=n;
 frame_derive(s->S,id,s->epoch,s->ctr,key,ns);u16(nonce,id);nonce[3]=64;u32(nonce+4,s->epoch);u64(nonce+8,s->ctr);
 u16(ad,id);ad[2]=n+8;ad[3]=0;ad[4]=64;u32(ad+6,s->epoch);u64(ad+10,s->ctr);ad[18]=n;
 aead_encrypt(key,nonce,ad,sizeof(ad),pt,n,r->ct,tag);memcpy(r->tag,tag,8);memcpy(s->S,ns,16);s->ctr++;
}
static int verify_at(const uint8_t S[16],uint16_t id,uint32_t e,uint64_t ctr,const Rec*r,uint8_t NS[16]){
 if(r->epoch!=e||r->ctr!=ctr)return 0;uint8_t key[16],nonce[16]={0},ad[19]={0},pt[8];frame_derive(S,id,e,ctr,key,NS);u16(nonce,id);nonce[3]=64;u32(nonce+4,e);u64(nonce+8,ctr);u16(ad,id);ad[2]=r->len+8;ad[3]=0;ad[4]=64;u32(ad+6,e);u64(ad+10,ctr);ad[18]=r->len;return aead_decrypt_verify_trunc(key,nonce,ad,sizeof(ad),r->ct,r->len,r->tag,8,pt);
}
static int recv_search(Node*r,uint16_t id,const Rec*rec,int W){
 if(rec->epoch!=r->epoch||rec->ctr<r->ctr)return 0;uint8_t tmp[16],next[16];memcpy(tmp,r->S,16);for(int k=0;k<W;k++){uint64_t c=r->ctr+k;if(verify_at(tmp,id,r->epoch,c,rec,next)){memcpy(r->S,next,16);r->ctr=c+1;return 1;}uint8_t key[16];frame_derive(tmp,id,r->epoch,c,key,next);memcpy(tmp,next,16);}return 0;
}
static void ctrl_nonce(uint16_t id,uint32_t e,uint8_t type,uint8_t n[16]){memset(n,0,16);u16(n,id);n[2]=type;u32(n+4,e);}
static void ctrl_tag(const uint8_t K[16],uint16_t id,uint8_t type,uint32_t olde,uint32_t newe,uint64_t nR,uint64_t nS,uint8_t out[8]){
 uint8_t nonce[16],ad[27],tag[16],dummy=0;ctrl_nonce(id,olde,type,nonce);u16(ad,id);ad[2]=type;u32(ad+3,olde);u32(ad+7,newe);u64(ad+11,nR);u64(ad+19,nS);aead_encrypt(K,nonce,ad,sizeof(ad),&dummy,0,&dummy,tag);memcpy(out,tag,8);
}
static int ctrl_verify(const uint8_t K[16],uint16_t id,uint8_t type,uint32_t olde,uint32_t newe,uint64_t nR,uint64_t nS,const uint8_t tag[8]){
 uint8_t nonce[16],ad[27],dummy=0;ctrl_nonce(id,olde,type,nonce);u16(ad,id);ad[2]=type;u32(ad+3,olde);u32(ad+7,newe);u64(ad+11,nR);u64(ad+19,nS);return aead_decrypt_verify_trunc(K,nonce,ad,sizeof(ad),&dummy,0,tag,8,&dummy);
}
static void epoch_derive(const uint8_t E[16],uint16_t id,uint32_t ne,uint64_t nR,uint64_t nS,uint8_t EN[16]){uint8_t m[38];memcpy(m,E,16);u16(m+16,id);u32(m+18,ne);u64(m+22,nR);u64(m+30,nS);const uint8_t c[]="RASP-CAN/EPOCH";ascon_cxof128_c(m,sizeof(m),c,sizeof(c)-1,EN,16);}
static uint64_t start_req(Node*r,uint16_t id,uint8_t tag[8]){r->outstanding=rng64();r->has_outstanding=1;ctrl_tag(r->KR,id,1,r->epoch,r->epoch,r->outstanding,0,tag);return r->outstanding;}
static int sender_sync(Node*s,uint16_t id,uint64_t nR,const uint8_t reqtag[8],SyncResp*resp){if(!ctrl_verify(s->KR,id,1,s->epoch,s->epoch,nR,0,reqtag))return 0;resp->olde=s->epoch;resp->newe=s->epoch+1;resp->nR=nR;resp->nS=rng64();ctrl_tag(s->KR,id,2,resp->olde,resp->newe,nR,resp->nS,resp->tag);return 1;}
static int receiver_accept_sync(Node*r,uint16_t id,const SyncResp*x,uint8_t pendingE[16],uint8_t pendingS[16],uint8_t ack[8]){if(!r->has_outstanding||x->nR!=r->outstanding||x->olde!=r->epoch||x->newe!=r->epoch+1)return 0;if(!ctrl_verify(r->KR,id,2,x->olde,x->newe,x->nR,x->nS,x->tag))return 0;epoch_derive(r->E,id,x->newe,x->nR,x->nS,pendingE);traffic_init(pendingE,id,x->newe,pendingS);ctrl_tag(pendingE,id,3,x->olde,x->newe,x->nR,x->nS,ack);return 1;}
static int sender_commit_sync(Node*s,uint16_t id,const SyncResp*x,const uint8_t ack[8]){uint8_t en[16],sn[16];epoch_derive(s->E,id,x->newe,x->nR,x->nS,en);if(!ctrl_verify(en,id,3,x->olde,x->newe,x->nR,x->nS,ack))return 0;traffic_init(en,id,x->newe,sn);memcpy(s->E,en,16);memcpy(s->S,sn,16);s->epoch=x->newe;s->ctr=0;return 1;}
static void receiver_commit_sync(Node*r,const SyncResp*x,const uint8_t en[16],const uint8_t sn[16]){memcpy(r->E,en,16);memcpy(r->S,sn,16);r->epoch=x->newe;r->ctr=0;r->has_outstanding=0;}
static void init_nodes(Node*a,Node*b,uint16_t id){randbytes(a->E,16);randbytes(a->KR,16);a->epoch=1;a->ctr=0;memcpy(b->E,a->E,16);memcpy(b->KR,a->KR,16);b->epoch=1;b->ctr=0;a->has_outstanding=b->has_outstanding=0;traffic_init(a->E,id,1,a->S);memcpy(b->S,a->S,16);}

int main(void){const uint16_t id=0x164;Node s,r;init_nodes(&s,&r,id);long made=0,accepted=0,dropped=0,replay_reject=0,tamper_reject=0,reset_sync=0,stale_sync_reject=0,state_mismatch=0,needs_sync=0;
 for(int i=0;i<50000;i++){
   uint8_t pt[8];randbytes(pt,8);Rec q;make_rec(&s,id,pt,8,&q);made++;
   uint64_t z=rng64()%1000;
   if(z<35){dropped++; int extra=(int)(rng64()%8); for(int b=0;b<extra;b++){uint8_t xp[8];randbytes(xp,8);Rec xq;make_rec(&s,id,xp,8,&xq);made++;dropped++;} continue;}
   if(z>=35&&z<45){Rec bad=q;bad.tag[rng64()%8]^=1u<<(rng64()%8); if(!recv_search(&r,id,&bad,4))tamper_reject++; else {fprintf(stderr,"tamper accepted\n");return 2;}}
   if(!recv_search(&r,id,&q,4)){needs_sync++;uint8_t rt[8],pe[16],ps[16],ack[8];uint64_t nr=start_req(&r,id,rt);SyncResp x;if(!sender_sync(&s,id,nr,rt,&x)||!receiver_accept_sync(&r,id,&x,pe,ps,ack)||!sender_commit_sync(&s,id,&x,ack)){fprintf(stderr,"sync fail\n");return 3;}receiver_commit_sync(&r,&x,pe,ps);reset_sync++;continue;} else accepted++;
   if((rng64()%200)==0){if(!recv_search(&r,id,&q,4))replay_reject++;else {fprintf(stderr,"replay accepted\n");return 4;}}
   if(memcmp(s.S,r.S,16)!=0 && s.ctr==r.ctr){state_mismatch++;return 5;}
   if((rng64()%700)==0){ // receiver volatile reset; exercise epoch sync
      memset(r.S,0,16);r.ctr=0;uint8_t rt[8],pe[16],ps[16],ack[8];uint64_t nr=start_req(&r,id,rt);SyncResp old,x;if(!sender_sync(&s,id,nr,rt,&old)){return 6;}
      // abandon old request and create a fresh one; delayed old response must fail
      uint8_t rt2[8];uint64_t nr2=start_req(&r,id,rt2);if(receiver_accept_sync(&r,id,&old,pe,ps,ack)){fprintf(stderr,"stale sync accepted\n");return 7;}stale_sync_reject++;
      if(!sender_sync(&s,id,nr2,rt2,&x)||!receiver_accept_sync(&r,id,&x,pe,ps,ack)||!sender_commit_sync(&s,id,&x,ack)){return 8;}receiver_commit_sync(&r,&x,pe,ps);reset_sync++;
   }
 }
 // randomized delayed/replayed ESYNC-only campaign
 for(int i=0;i<10000;i++){
   uint8_t t1[8],t2[8],pe[16],ps[16],ack[8];uint64_t n1=start_req(&r,id,t1);SyncResp old;if(!sender_sync(&s,id,n1,t1,&old))return 9;uint64_t n2=start_req(&r,id,t2);if(receiver_accept_sync(&r,id,&old,pe,ps,ack)){fprintf(stderr,"delayed accepted\n");return 10;}stale_sync_reject++;SyncResp x;if(!sender_sync(&s,id,n2,t2,&x)||!receiver_accept_sync(&r,id,&x,pe,ps,ack)||!sender_commit_sync(&s,id,&x,ack))return 11;receiver_commit_sync(&r,&x,pe,ps);reset_sync++;
 }
 printf("made=%ld accepted=%ld dropped=%ld needs_sync=%ld tamper_reject=%ld replay_reject=%ld epoch_sync_commits=%ld stale_delayed_sync_reject=%ld state_mismatch=%ld unauthorized_accept=0\n",made,accepted,dropped,needs_sync,tamper_reject,replay_reject,reset_sync,stale_sync_reject,state_mismatch);
 return 0;
}
