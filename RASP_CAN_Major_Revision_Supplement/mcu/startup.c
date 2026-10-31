#include <stdint.h>
extern uint32_t _etext,_sdata,_edata,_sbss,_ebss,_estack; extern int main(void);
void Reset_Handler(void){uint32_t*s=&_etext,*d=&_sdata;while(d<&_edata)*d++=*s++;for(d=&_sbss;d<&_ebss;)*d++=0;main();for(;;);}
void Default_Handler(void){for(;;);}
__attribute__((section(".vectors"),used)) void (*const vt[16])(void)={(void(*)(void))&_estack,Reset_Handler,Default_Handler,Default_Handler,Default_Handler,Default_Handler,Default_Handler,0,0,0,0,Default_Handler,Default_Handler,0,Default_Handler,Default_Handler};
void exit(int c){ (void)c; register uint32_t r0 __asm__("r0")=0x18; register uint32_t r1 __asm__("r1")=0x20026; __asm__ volatile("bkpt 0xAB"::"r"(r0),"r"(r1)); for(;;); }
