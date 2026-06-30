// Report Ghidra references to selected AMSS service/debug strings.
// @category BCM2153

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class FindAmssServiceStringRefs extends GhidraScript {
    private static class Target {
        long address;
        String label;

        Target(long address, String label) {
            this.address = address;
            this.label = label;
        }
    }

    private static final Target[] TARGETS = new Target[] {
        new Target(0x80318840L, "memory_debug_i32"),
        new Target(0x80318868L, "memory_debug_char"),
        new Target(0x80318890L, "memory_debug_i16"),
        new Target(0x803188b8L, "memory_debug_read_help"),
        new Target(0x80318928L, "memory_debug_write_help"),
        new Target(0x80302370L, "ATCmd_MUSBTEST_default"),
        new Target(0x80302684L, "ATCmd_MUSBTST_case_21_cal"),
        new Target(0x80302768L, "ATCmd_MUSBTST_case_40_uart"),
        new Target(0x8030597cL, "CAPI2AT_Q"),
        new Target(0x80305a54L, "CP2ATC_Q"),
        new Target(0x8030bde0L, "CAPI2_atc_entry"),
        new Target(0x80311ca4L, "CAPI2_FFS_Control_enter"),
        new Target(0x80311ce0L, "CAPI2_FFS_Control_fail"),
        new Target(0x80311d00L, "CAPI2_FFS_Control_exit"),
        new Target(0x80317534L, "download_script_prompt"),
        new Target(0x80372764L, "normal_cal_download_mode")
    };

    @Override
    protected void run() throws Exception {
        String outPath = getScriptArgs().length > 0
            ? getScriptArgs()[0]
            : "out/amss_service_refs/ghidra_string_refs.md";
        File outFile = new File(outPath);
        File parent = outFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        try (PrintWriter out = new PrintWriter(new FileWriter(outFile))) {
            out.println("# Ghidra AMSS service string references");
            out.println();
            out.println("Program: `" + currentProgram.getName() + "`");
            out.println();
            out.println("| Label | Target | Refs | First refs |");
            out.println("| --- | ---: | ---: | --- |");
            for (Target target : TARGETS) {
                Address targetAddress = toAddr(target.address);
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(targetAddress);
                int count = 0;
                StringBuilder first = new StringBuilder();
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    count++;
                    if (count <= 8) {
                        Address from = ref.getFromAddress();
                        Function function = getFunctionContaining(from);
                        if (first.length() > 0) {
                            first.append("; ");
                        }
                        first.append("`").append(from).append("`");
                        if (function != null) {
                            first.append(" in `").append(function.getName()).append("`");
                        }
                    }
                }
                out.println("| `" + target.label + "` | `" + targetAddress + "` | " + count + " | " + first.toString() + " |");
            }
        }
        println("Wrote " + outFile.getPath());
    }
}
