RASP-CAN Major-Revision Supplement

This package contains the software artifacts available in the revision workspace.

Key additions for the major revision:
- src/ascon_state_fault_harness.c: randomized state/recovery fault harness linked to the actual Ascon implementation.
- results/ascon_state_fault_results.txt: run summary (56,106 attempts; zero unauthorized accepts; zero post-sync state mismatches; stale/delayed EPOCH-SYNC rejection exercised).
- MCU/QEMU instruction-count harness and outputs: architecture-level dynamic instruction counts only, not physical MCU WCET or energy.
- Loss/H/W and side-channel sensitivity scripts/results from the supplied revision experiment package.

Important boundaries:
1. The HCRL/OTIDS mixed-capture rows are communication/compressibility inputs, not attack-detection efficacy tests.
2. QEMU instruction counts are not silicon cycle, WCET, or energy measurements.
3. The EPOCH-SYNC state machine is exercised by the actual-Ascon randomized host harness but is not integrated into the original large HCRL trace driver and has not been model-checked.
4. No DOI-bearing public repository or immutable commit hash was supplied in the project materials. Before resubmission, deposit this exact artifact snapshot in a public archival repository and add its DOI/commit hash to the manuscript if required by the editor.
