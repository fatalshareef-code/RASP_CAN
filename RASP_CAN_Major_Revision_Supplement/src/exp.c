#include "core.inc"
/* OTIDS/HCRL txt parser: "Timestamp: t  ID: 0220  000  DLC: 8  29 c5 ..." */
static int parse_txt(char *line,double *ts,unsigned *id,int *dlc,uint8_t d[8]){
  char *p=strstr(line,"Timestamp:"); if(!p) return 0; *ts=strtod(p+10,NULL);
  p=strstr(line,"ID:"); if(!p) return 0; *id=strtoul(p+3,NULL,16);
  p=strstr(line,"DLC:"); if(!p) return 0; char *e; *dlc=(int)strtol(p+4,&e,10);
  memset(d,0,8); int n=0; p=e; while(*p&&n<*dlc&&n<8){ while(*p==' '||*p=='\t')p++; if(hexval(p[0])>=0&&hexval(p[1])>=0){d[n++]=(hexval(p[0])<<4)|hexval(p[1]);p+=2;} else break; }
  return n==*dlc;
}
static void pass_period(const char *path){ /* per-ID mean period over the whole file */
  static double first[2048],last[2048]; static long cnt[2048]; FILE*f=fopen(path,"r"); char*line=NULL;size_t cap=0;
  while(getline(&line,&cap,f)!=-1){double ts;unsigned id;int dlc;uint8_t d[8];if(!parse_txt(line,&ts,&id,&dlc,d)||id>=2048)continue; if(!cnt[id])first[id]=ts; last[id]=ts; cnt[id]++;}
  for(int i=0;i<2048;i++) if(cnt[i]>1){double T=(last[i]-first[i])/(cnt[i]-1); if(IDPERIOD[i]==0||T<IDPERIOD[i])IDPERIOD[i]=T;}
  free(line); fclose(f);
}
static void run_file(const char *path,int fileidx){
  FILE *f=fopen(path,"r");if(!f){perror(path);exit(2);}char *line=NULL;size_t cap=0;double t0=0;int first=1;
  while(getline(&line,&cap,f)!=-1){double ts;unsigned id;int dlc;uint8_t data[8];
    if(!parse_txt(line,&ts,&id,&dlc,data)){fprintf(stderr,"parse fail %s",line);exit(2);}
    if(first){t0=ts;first=0;}double rel=ts-t0;int seg=(fileidx==0?(rel<250?0:2):(fileidx==1?(rel<250?1:3):4));
    Stats *s=&segstats[seg];s->inputs++;if(!seg_seen[seg]){seg_first[seg]=ts;seg_seen[seg]=1;}seg_last[seg]=ts;
    s->raw_nominal_bits+=nominal_bits(dlc);s->raw_worst_bits+=worst_bits(dlc); s->raw_exact_bits+=can_exact_bits(id,dlc,data);
    if(dlc!=8 && !PADSHORT){s->rasp_exact_bits+=can_exact_bits(id,dlc,data);s->passthrough++;s->physical_frames++;s->physical_dlc_bytes+=dlc;s->dlc[dlc]++;s->rasp_nominal_bits+=nominal_bits(dlc);s->rasp_worst_bits+=worst_bits(dlc);continue;}
    /* PADSHORT: zero-pad to 8 bytes; the pad is deterministic so the receiver strips it using the authenticated original DLC */
    Ctx *c=&contexts[seg][id];uint32_t epoch=seg+1;if(!c->initialized)init_ctx(c,id,epoch);
    Stats *ids=(seg==0||seg==1)?&idstats[id]:NULL;if(ids){ids->inputs++;ids->raw_nominal_bits+=nominal_bits(dlc);ids->raw_worst_bits+=worst_bits(dlc);}
    process_payload(s,ids,c,id,epoch,data);
  }
  free(line);fclose(f);
}
int main(int argc,char**argv){
  /* usage: exp OUTDIR H PADSHORT PERID_H SEQFILE|- fuzzy imp dos */
  const char*out=argv[1]; HINT=atoi(argv[2]); PADSHORT=atoi(argv[3]); PERID_H=atoi(argv[4]);
  if(strcmp(argv[5],"-"))SEQ=fopen(argv[5],"w");
  if(PERID_H){pass_period(argv[6]);pass_period(argv[7]);pass_period(argv[8]);}
  clock_t t=clock(); run_file(argv[6],0); run_file(argv[7],1); run_file(argv[8],2);
  char p[512]; sprintf(p,"%s/table9.csv",out); write_table4(p); sprintf(p,"%s/table10.csv",out); write_table5(p); sprintf(p,"%s/table11.csv",out); write_table6(p);
  sprintf(p,"%s/summary.json",out); write_json(p,(double)(clock()-t)/CLOCKS_PER_SEC);
  sprintf(p,"%s/stuffing.csv",out); FILE*g=fopen(p,"w"); fprintf(g,"segment,duration,raw_nominal,raw_exact,raw_worst,rasp_nominal,rasp_exact,rasp_worst\n");
  for(int i=0;i<NSEGS;i++){Stats*s=&segstats[i];double dur=seg_last[i]-seg_first[i],k=100.0/(BUS_RATE*dur);fprintf(g,"%s,%.3f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",seg_name[i],dur,k*s->raw_nominal_bits,k*s->raw_exact_bits,k*s->raw_worst_bits,k*s->rasp_nominal_bits,k*s->rasp_exact_bits,k*s->rasp_worst_bits);} fclose(g);
  if(SEQ)fclose(SEQ); return 0;
}
