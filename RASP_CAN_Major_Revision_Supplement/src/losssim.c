#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
/* Record-level loss/recovery simulator over the action sequences emitted by the RASP-CAN C stack. */
typedef struct{int seg,id;}Key;
static int *act; static int *sid; static long N;
static uint64_t rs=0x9E3779B97F4A7C15ULL; static double urand(){rs^=rs<<13;rs^=rs>>7;rs^=rs<<17;return (rs>>11)*(1.0/9007199254740992.0);}
int main(int argc,char**argv){
  const char*file=argv[1]; int W=atoi(argv[2]); double p=atof(argv[3]); double B=atof(argv[4]); int req=atoi(argv[5]); rs^=atoi(argv[6]);
  FILE*f=fopen(file,"r"); long cap=1<<22; act=malloc(cap*sizeof(int)); sid=malloc(cap*sizeof(int)); int s,a; unsigned id; N=0;
  while(fscanf(f,"%d,%x,%d",&s,&id,&a)==3){ if(N==cap){cap*=2;act=realloc(act,cap*sizeof(int));sid=realloc(sid,cap*sizeof(int));} act[N]=a; sid[N]=s*4096+id; N++; }
  fclose(f);
  /* per-stream state */
  static long cl[5*4096]; static int st[5*4096]; static int bad[5*4096]; static long run[5*4096]; static long k_of[5*4096];
  for(int i=0;i<5*4096;i++){cl[i]=-1;st[i]=0;bad[i]=0;run[i]=0;k_of[i]=0;}
  double pGB=(B<=1.0)? p/(1-p) : p/(B*(1-p)); double pBG=(B<=1.0)?1.0:1.0/B;
  long recv=0,lost=0,attempts=0,wexh=0,supp=0,extra=0,maxrun=0,gaps=0,reqs=0; double sumrun=0; long nruns=0;
  for(long n=0;n<N;n++){
    int q=sid[n]; long k=k_of[q]++; int A=act[n];
    /* loss process (per stream) */
    int L; if(bad[q]){ L=1; if(urand()<pBG) bad[q]=0; } else { if(urand()<pGB){bad[q]=1; L=1; if(urand()<pBG) bad[q]=0;} else L=0; }
    if(B<=1.0){ L = urand()<p; }
    if(L){lost++; continue;}
    recv++;
    int delivered=0;
    #define REQUEST() do{ if(req){ reqs++; extra+=4; int ok=1; for(int r=0;r<4;r++) if(urand()<p) ok=0; if(ok){ st[q]=0; cl[q]=k; delivered=1; } } }while(0)
    if(st[q]==2){ /* window lost: counter unknown */
      if(A==2){ attempts+=1; st[q]=0; cl[q]=k; delivered=1; }
      else { attempts+=W; REQUEST(); }
    } else {
      long g=k-cl[q]-1;
      if(g+1>W){ attempts+=W; wexh++; st[q]=2; REQUEST(); }
      else {
        attempts+=g+1; cl[q]=k; if(g>0) gaps++;
        if(A!=0){ st[q]=0; delivered=1; }                 /* self-contained escape/checkpoint */
        else if(g==0 && st[q]==0){ delivered=1; }
        else { st[q]=1; REQUEST(); }                       /* predictive record after a gap */
      }
    }
    if(delivered){ if(run[q]>0){sumrun+=run[q];nruns++; if(run[q]>maxrun)maxrun=run[q]; run[q]=0;} }
    else { supp++; run[q]++; }
  }
  for(int i=0;i<5*4096;i++) if(run[i]>0){sumrun+=run[i];nruns++; if(run[i]>maxrun)maxrun=run[i];}
  printf("%d,%g,%g,%d,%ld,%ld,%.4f,%.2f,%.1f,%.1f,%.3f,%ld,%.4f\n",W,p,B,req,recv,lost,(double)attempts/recv,1e6*wexh/recv,1e6*supp/recv,1e6*reqs/recv,nruns?sumrun/nruns:0,maxrun,100.0*extra/N);
  return 0;
}
