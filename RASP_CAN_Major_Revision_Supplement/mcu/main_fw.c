#include <stdint.h>
extern int run_op(int);
#ifndef OP
#define OP 0
#endif
#ifndef REP
#define REP 1
#endif
extern void exit(int);
int main(void){ for(int i=0;i<REP;i++) run_op(OP); exit(0); }
