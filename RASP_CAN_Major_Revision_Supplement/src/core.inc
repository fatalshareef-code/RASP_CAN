#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include "ascon_rasp.c"

#define MAX_ID 2048
#define NSEGS 5
int HINT=100; int PADSHORT=0; FILE *SEQ=NULL; double IDPERIOD[2048]; int PERID_H=0; double TTOL=1.0;
#define PROFILE32 32
#define BUS_RATE 500000.0

enum {M_RAW=0,M_HOLD=1,M_D1=2,M_D2=3,M_XOR=4};
const char *mode_name[5]={"RAW","HOLD","D1","D2","XOR"};
const char *seg_name[NSEGS]={"Normal-Fuzzy","Normal-Impersonation","Fuzzy-attack","Impersonation-attack","DoS-mixed-attack"};

typedef struct {
    uint64_t inputs,protected,passthrough,normal,escape,checkpoint;
    uint64_t dlc[9],modes[5],z[17];
    uint64_t meaningful_bits,physical_frames,physical_dlc_bytes;
    uint64_t raw_nominal_bits,raw_worst_bits,rasp_nominal_bits,rasp_worst_bits;
    uint64_t crypto_fail,decode_fail; uint64_t raw_exact_bits,rasp_exact_bits;
} Stats;

typedef struct {
    int initialized,has_prev,has_prev2;
    uint8_t state[16],recovery[16],prev[8],prev2[8];
    uint64_t counter,accepted;
} Ctx;

static Ctx contexts[NSEGS][MAX_ID];
static Stats segstats[NSEGS], idstats[MAX_ID];
static double seg_first[NSEGS],seg_last[NSEGS];
static int seg_seen[NSEGS];
static const uint8_t MASTER[16]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};

static uint64_t choose_u64(uint64_t n, uint64_t k) {
    if (k > n) return 0;
    if (k > n - k) k = n - k;
    uint64_t r = 1;
    for (uint64_t i = 1; i <= k; i++) r = r * (n - k + i) / i;
    return r;
}
static int rbits(int z){uint64_t c=choose_u64(16,z);int b=0;uint64_t v=1;while(v<c){v<<=1;b++;}return b;}
static int codec_bits(int z){return 10+rbits(z)+4*z;}
static uint64_t rank_subset(const int *pos,int z){
    uint64_t rank=0;int prev=-1;
    for(int i=0;i<z;i++){
        for(int v=prev+1;v<pos[i];v++)rank+=choose_u64(16-v-1,z-i-1);
        prev=pos[i];
    }
    return rank;
}
static int unrank_subset(int z,uint64_t rank,int *pos){
    int prev=-1;
    for(int i=0;i<z;i++){
        int found=0;
        for(int v=prev+1;v<16;v++){
            uint64_t c=choose_u64(16-v-1,z-i-1);
            if(rank<c){pos[i]=v;prev=v;found=1;break;} rank-=c;
        }
        if(!found)return 0;
    }
    return rank==0;
}
static void to_nibbles(const uint8_t b[8],uint8_t n[16]){for(int i=0;i<8;i++){n[2*i]=b[i]>>4;n[2*i+1]=b[i]&15;}}
static void from_nibbles(const uint8_t n[16],uint8_t b[8]){for(int i=0;i<8;i++)b[i]=(n[2*i]<<4)|n[2*i+1];}
static void residual(const uint8_t cur[16],const uint8_t prev[16],const uint8_t prev2[16],int mode,uint8_t r[16]){
    for(int i=0;i<16;i++){
        if(mode==M_HOLD||mode==M_D1)r[i]=(cur[i]-prev[i])&15;
        else if(mode==M_D2)r[i]=(cur[i]-(2*prev[i]-prev2[i]))&15;
        else r[i]=cur[i]^prev[i];
    }
}
static void inverse(const uint8_t r[16],const uint8_t prev[16],const uint8_t prev2[16],int mode,uint8_t cur[16]){
    for(int i=0;i<16;i++){
        if(mode==M_HOLD||mode==M_D1)cur[i]=(prev[i]+r[i])&15;
        else if(mode==M_D2)cur[i]=(2*prev[i]-prev2[i]+r[i])&15;
        else cur[i]=prev[i]^r[i];
    }
}
typedef struct{int valid,L,z,pri,mode;uint8_t r[16];} Candidate;
static Candidate choose_mode(const uint8_t payload[8],const Ctx *ctx){
    Candidate best={0,999,0,0,0,{0}};uint8_t cur[16],p[16],p2[16],r[16];to_nibbles(payload,cur);if(ctx->has_prev)to_nibbles(ctx->prev,p);if(ctx->has_prev2)to_nibbles(ctx->prev2,p2);
    const int modes[4]={M_HOLD,M_D2,M_XOR,M_D1};
    for(int pri=0;pri<4;pri++){
        int m=modes[pri];if(!ctx->has_prev)continue;if(m==M_D2&&!ctx->has_prev2)continue;
        residual(cur,p,p2,m,r);int z=0;for(int i=0;i<16;i++)if(r[i])z++;int L=codec_bits(z);
        if(!best.valid||L<best.L||(L==best.L&&z<best.z)||(L==best.L&&z==best.z&&pri<best.pri)){
            best.valid=1;best.L=L;best.z=z;best.pri=pri;best.mode=m;memcpy(best.r,r,16);
        }
    }
    return best;
}
static int pack_normal(const Candidate *c,uint8_t body[4],int *bodylen,int *nbits_out,uint64_t *rank_out){
    int pos[16],z=0;uint8_t vals[16];for(int i=0;i<16;i++)if(c->r[i]){pos[z]=i;vals[z]=c->r[i];z++;}
    int rb=rbits(z),nb=10+rb+4*z,nbytes=(nb+7)/8;if(nbytes>4)return 0;uint64_t rank=rank_subset(pos,z);
    uint64_t x=((uint64_t)c->mode<<5)|z;if(rb)x=(x<<rb)|rank;for(int i=0;i<z;i++)x=(x<<4)|vals[i];x<<=(nbytes*8-nb);
    for(int i=0;i<nbytes;i++)body[i]=(x>>(8*(nbytes-1-i)))&0xff;
    *bodylen=nbytes;*nbits_out=nb;*rank_out=rank;return 1;
}
static int decode_normal(const uint8_t *body,int bodylen,const Ctx *ctx,uint8_t out[8],int *mode_out,int *z_out){
    int total=bodylen*8;uint64_t x=0;for(int i=0;i<bodylen;i++)x=(x<<8)|body[i];uint64_t header=x>>(total-10);int typ=(header>>8)&3,mode=(header>>5)&7,z=header&31;if(typ!=0||z>16||!(mode==M_HOLD||mode==M_D1||mode==M_D2||mode==M_XOR))return 0;
    if (!ctx->has_prev || (mode == M_D2 && !ctx->has_prev2)) return 0;
    int rb = rbits(z);
    int cursor = total - 10;
    uint64_t rank = rb ? ((x >> (cursor - rb)) & (((uint64_t)1 << rb) - 1)) : 0;
    cursor -= rb;
    int pos[16];
    if (!unrank_subset(z, rank, pos)) return 0;
    uint8_t r[16] = {0};
    for (int i = 0; i < z; i++) {
        cursor -= 4;
        r[pos[i]] = (x >> cursor) & 15;
    }
    if (cursor > 0 && (x & (((uint64_t)1 << cursor) - 1))) return 0;
    uint8_t p[16],p2[16],cur[16];to_nibbles(ctx->prev,p);if(ctx->has_prev2)to_nibbles(ctx->prev2,p2);inverse(r,p,p2,mode,cur);from_nibbles(cur,out);*mode_out=mode;*z_out=z;return 1;
}
static int nominal_bits(int dlc){return 47+8*dlc;}
static int worst_bits(int dlc){int region=34+8*dlc;return nominal_bits(dlc)+(region-1)/4;}

/* exact Classic CAN base-frame length with bit stuffing over SOF..CRC (ISO 11898-1) */
static int can_exact_bits(unsigned id,int dlc,const uint8_t*d){
  uint8_t b[128]; int n=0; b[n++]=0; for(int i=10;i>=0;i--) b[n++]=(id>>i)&1; b[n++]=0; b[n++]=0; b[n++]=0;
  for(int i=3;i>=0;i--) b[n++]=(dlc>>i)&1; for(int k=0;k<dlc;k++) for(int i=7;i>=0;i--) b[n++]=(d[k]>>i)&1;
  uint16_t crc=0; for(int i=0;i<n;i++){ int nxt=b[i]^((crc>>14)&1); crc=(crc<<1)&0x7FFF; if(nxt) crc^=0x4599; }
  for(int i=14;i>=0;i--) b[n++]=(crc>>i)&1;
  int stuffed=0,run=1; int last=b[0];
  for(int i=1;i<n;i++){ if(b[i]==last){ run++; if(run==5){ stuffed++; last=!last; run=1; } } else { last=b[i]; run=1; } }
  return n+stuffed+13; /* + CRC delim, ACK(2), EOF(7), IFS(3) */
}
static void init_ctx(Ctx *c,uint16_t id,uint32_t epoch){
    uint8_t material[22];memcpy(material,MASTER,16);material[16]=id&0xff;material[17]=id>>8;for(int i=0;i<4;i++)material[18+i]=(epoch>>(8*i))&0xff;
    const uint8_t ci[]="RASP-CAN/INIT",cr[]="RASP-CAN/RECOVERY";ascon_cxof128_c(material,22,ci,sizeof(ci)-1,c->state,16);ascon_cxof128_c(material,22,cr,sizeof(cr)-1,c->recovery,16);c->initialized=1;
}
static void add_action_stats(Stats *s,int action,int dlc,int nbits,int mode,int z){
    if(action==0){s->normal++;s->modes[mode]++;s->z[z]++;s->meaningful_bits+=nbits;s->physical_frames++;s->physical_dlc_bytes+=dlc;s->dlc[dlc]++;s->rasp_nominal_bits+=nominal_bits(dlc);s->rasp_worst_bits+=worst_bits(dlc);}
    else if(action==1){s->escape++;s->meaningful_bits+=64;s->physical_frames+=2;s->physical_dlc_bytes+=16;s->dlc[8]+=2;s->rasp_nominal_bits+=2*nominal_bits(8);s->rasp_worst_bits+=2*worst_bits(8);}
    else{s->checkpoint++;s->meaningful_bits+=64;s->physical_frames+=3;s->physical_dlc_bytes+=24;s->dlc[8]+=3;s->rasp_nominal_bits+=3*nominal_bits(8);s->rasp_worst_bits+=3*worst_bits(8);}
}
static void process_payload(Stats *s,Stats *ids,Ctx *ctx,uint16_t id,uint32_t epoch,const uint8_t payload[8]){
    s->protected++;if(ids)ids->protected++;
    int Hc=HINT; if(PERID_H){double T=IDPERIOD[id]; int h=(int)(TTOL/T+0.5); if(h<10)h=10; if(h>1000)h=1000; Hc=h;} int chk=((ctx->accepted+1)%Hc)==0;int action,dlc=0,nbits=64,mode=0,z=0,ok=0;uint8_t ns[16],record[32];size_t olen=0;
    if(chk){action=2;ok=rasp_checkpoint_verify_c(ctx->recovery,id,epoch,ctx->counter,payload,ns,ctx->state,record);memcpy(ctx->prev,payload,8);ctx->has_prev=1;ctx->has_prev2=0;}
    else{
        Candidate c=choose_mode(payload,ctx);
        if(c.valid&&c.L<=32){action=0;uint8_t body[4],decoded[8];int bl,dm,dz;uint64_t rank;if(!pack_normal(&c,body,&bl,&nbits,&rank)){fprintf(stderr,"pack fail\n");exit(3);}dlc=bl+4;ok=rasp_protect_verify_c(ctx->state,id,epoch,ctx->counter,PROFILE32,0,body,bl,4,ns,record,&olen);if(!decode_normal(body,bl,ctx,decoded,&dm,&dz)||memcmp(decoded,payload,8)||dm!=c.mode||dz!=c.z){s->decode_fail++;if(ids)ids->decode_fail++;}mode=c.mode;z=c.z;if(ctx->has_prev){memcpy(ctx->prev2,ctx->prev,8);ctx->has_prev2=1;}memcpy(ctx->prev,payload,8);ctx->has_prev=1;}
        else{action=1;ok=rasp_protect_verify_c(ctx->state,id,epoch,ctx->counter,PROFILE32,1,payload,8,8,ns,record,&olen);if(olen!=16){s->decode_fail++;if(ids)ids->decode_fail++;}memcpy(ctx->prev,payload,8);ctx->has_prev=1;ctx->has_prev2=0;}
    }
    if(!ok){s->crypto_fail++;if(ids)ids->crypto_fail++;}
    memcpy(ctx->state,ns,16);ctx->counter++;ctx->accepted++;
{uint64_t eb=0; if(action==0) eb=can_exact_bits(id,dlc,record); else if(action==1) eb=can_exact_bits(id,8,record)+can_exact_bits(id,8,record+8); else eb=can_exact_bits(id,8,record)+can_exact_bits(id,8,record+8)+can_exact_bits(id,8,record+16); s->rasp_exact_bits+=eb; if(ids) ids->rasp_exact_bits+=eb;}
    if(SEQ)fprintf(SEQ,"%d,%x,%d\n",(int)(s-segstats),id,action);add_action_stats(s,action,dlc,nbits,mode,z);if(ids)add_action_stats(ids,action,dlc,nbits,mode,z);
}
int hexval(char c){if(c>='0'&&c<='9')return c-'0';c=tolower((unsigned char)c);if(c>='a'&&c<='f')return c-'a'+10;return -1;}
static int parse_line(char *line,double *ts,unsigned *id,int *dlc,uint8_t data[8]){
    char *p=line,*e;*ts=strtod(p,&e);if(e==p||*e!=',')return 0;p=e+1;*id=strtoul(p,&e,16);if(*e!=',')return 0;p=e+1;
    e=strchr(p,',');if(!e)return 0;p=e+1;*dlc=(int)strtol(p,&e,10);if(*e!=',')return 0;p=e+1;
    int n=0;while(*p&&n<8){if(*p=='\''&&hexval(p[1])>=0&&hexval(p[2])>=0&&p[3]=='\''){data[n++]=(hexval(p[1])<<4)|hexval(p[2]);p+=4;}else p++;}
    return (*dlc==8)?(n==8):1;
}
static void process_file(const char *path,int fileidx){
    FILE *f=fopen(path,"r");if(!f){perror(path);exit(2);}char *line=NULL;size_t cap=0;ssize_t len;getline(&line,&cap,f);double t0=0;int first=1;
    while((len=getline(&line,&cap,f))!=-1){double ts;unsigned id;int dlc;uint8_t data[8];if(!parse_line(line,&ts,&id,&dlc,data)){fprintf(stderr,"parse fail %s\n",line);exit(2);}if(first){t0=ts;first=0;}double rel=ts-t0;int seg=(fileidx==0?(rel<250?0:2):(fileidx==1?(rel<250?1:3):4));Stats *s=&segstats[seg];s->inputs++;if(!seg_seen[seg]){seg_first[seg]=ts;seg_seen[seg]=1;}seg_last[seg]=ts;s->raw_nominal_bits+=nominal_bits(dlc);s->raw_worst_bits+=worst_bits(dlc);
        if(dlc!=8){s->passthrough++;s->physical_frames++;s->physical_dlc_bytes+=dlc;s->dlc[dlc]++;s->rasp_nominal_bits+=nominal_bits(dlc);s->rasp_worst_bits+=worst_bits(dlc);continue;}
        if(id>=MAX_ID){fprintf(stderr,"extended ID unsupported %x\n",id);exit(2);}Ctx *c=&contexts[seg][id];uint32_t epoch=seg+1;if(!c->initialized)init_ctx(c,id,epoch);Stats *ids=(seg==0||seg==1)?&idstats[id]:NULL;if(ids){ids->inputs++;ids->raw_nominal_bits+=nominal_bits(8);ids->raw_worst_bits+=worst_bits(8);}process_payload(s,ids,c,id,epoch,data);
    }
    free(line);fclose(f);
}
static double pct(uint64_t a,uint64_t b){return b?100.0*a/b:0;}
static void write_table4(const char *path){
    FILE *f=fopen(path,"w");fprintf(f,"CAN ID,DLC=8 inputs,N32 normal (%%),E64 escape (%%),CHK64 (%%),Mean codec bits/input,Codec reduction (%%),Physical frames/input,Dominant predictor\n");
    int used[MAX_ID]={0};for(int k=0;k<9;k++){int best=-1;for(int i=0;i<MAX_ID;i++)if(!used[i]&&idstats[i].inputs&&(best<0||idstats[i].inputs>idstats[best].inputs))best=i;if(best<0)break;used[best]=1;Stats*s=&idstats[best];int dm=1;for(int m=2;m<=4;m++)if(s->modes[m]>s->modes[dm])dm=m;fprintf(f,"0x%03X,%llu,%.2f,%.2f,%.2f,%.2f,%.2f,%.4f,%s\n",best,(unsigned long long)s->inputs,pct(s->normal,s->protected),pct(s->escape,s->protected),pct(s->checkpoint,s->protected),(double)s->meaningful_bits/s->protected,100.0*(1.0-(double)s->meaningful_bits/(64.0*s->protected)),(double)s->physical_frames/s->protected,s->modes[dm]?mode_name[dm]:"-");}
    fclose(f);
}
static void write_table5(const char *path){FILE*f=fopen(path,"w");fprintf(f,"Trace segment,All input frames,Protected DLC=8,Coverage (%%),N32 (%%),E64 (%%),CHK64 (%%),DLC6,DLC7,DLC8 physical records,Frames/input,Crypto failures,Decode failures\n");for(int i=0;i<NSEGS;i++){Stats*s=&segstats[i];fprintf(f,"%s,%llu,%llu,%.2f,%.2f,%.2f,%.2f,%llu,%llu,%llu,%.4f,%llu,%llu\n",seg_name[i],(unsigned long long)s->inputs,(unsigned long long)s->protected,pct(s->protected,s->inputs),pct(s->normal,s->protected),pct(s->escape,s->protected),pct(s->checkpoint,s->protected),(unsigned long long)s->dlc[6],(unsigned long long)s->dlc[7],(unsigned long long)s->dlc[8],(double)s->physical_frames/s->inputs,(unsigned long long)s->crypto_fail,(unsigned long long)s->decode_fail);}fclose(f);}
static void write_table6(const char *path){FILE*f=fopen(path,"w");fprintf(f,"Trace segment,Duration (s),Input frames,Raw nominal load (%%),RASP nominal load (%%),Relative load change (%%),RASP worst-case stuffed (%%),Added physical frames\n");for(int i=0;i<NSEGS;i++){Stats*s=&segstats[i];double dur=seg_last[i]-seg_first[i];double raw=100.0*s->raw_nominal_bits/(BUS_RATE*dur),rasp=100.0*s->rasp_nominal_bits/(BUS_RATE*dur),worst=100.0*s->rasp_worst_bits/(BUS_RATE*dur);fprintf(f,"%s,%.6f,%llu,%.2f,%.2f,%+.2f,%.2f,%lld\n",seg_name[i],dur,(unsigned long long)s->inputs,raw,rasp,100.0*(rasp/raw-1.0),worst,(long long)s->physical_frames-(long long)s->inputs);}fclose(f);}
static void write_json(const char *path,double runtime){FILE*f=fopen(path,"w");fprintf(f,"{\n  \"configuration\": {\"profile\": \"P32-L\", \"H\": %d, \"W\": 4, \"anchor\": \"disabled\", \"bus_rate\": 500000, \"protected_dlc\": 8, \"D1_note\": \"D1 duplicates HOLD in the manuscript and never wins the tie-break\"},\n  \"runtime_seconds\": %.6f,\n  \"segments\": [\n",HINT,runtime);for(int i=0;i<NSEGS;i++){Stats*s=&segstats[i];fprintf(f,"    {\"name\":\"%s\",\"inputs\":%llu,\"protected\":%llu,\"normal\":%llu,\"escape\":%llu,\"checkpoint\":%llu,\"crypto_fail\":%llu,\"decode_fail\":%llu,\"modes\":{\"HOLD\":%llu,\"D1\":%llu,\"D2\":%llu,\"XOR\":%llu}}%s\n",seg_name[i],(unsigned long long)s->inputs,(unsigned long long)s->protected,(unsigned long long)s->normal,(unsigned long long)s->escape,(unsigned long long)s->checkpoint,(unsigned long long)s->crypto_fail,(unsigned long long)s->decode_fail,(unsigned long long)s->modes[M_HOLD],(unsigned long long)s->modes[M_D1],(unsigned long long)s->modes[M_D2],(unsigned long long)s->modes[M_XOR],i==NSEGS-1?"":",");}fprintf(f,"  ]\n}\n");fclose(f);}

