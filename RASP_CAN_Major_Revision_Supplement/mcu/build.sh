cpu=$1; op=$2; rep=$3; out=fw_${cpu}_${op}_${rep}.elf
arm-none-eabi-gcc -mcpu=$cpu -mthumb -O2 -ffunction-sections -fdata-sections -Wl,--gc-sections -DOP=$op -DREP=$rep -nostartfiles --specs=nano.specs --specs=nosys.specs -T link.ld startup.c main_fw.c ops.c -o $out 2>&1 | grep -iv warning | grep -v "^$" | head -3
