# usage: count.sh elf machine -> executed instruction count
timeout 300 qemu-system-arm -M $2 -nographic -semihosting -kernel $1 -accel tcg,one-insn-per-tb=on -d exec,nochain -D /tmp/q_$$.log >/dev/null 2>&1
grep -c "^Trace" /tmp/q_$$.log; rm -f /tmp/q_$$.log
