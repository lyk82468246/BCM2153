// Bounded script-global construction and frame lookup analysis; read-only report stays local.
// Run with -noanalysis -readOnly; function names below are analyst labels.
// @category BCM2153

import com.google.gson.GsonBuilder;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.SourceType;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ProbeShpAppScriptFrame extends GhidraScript {
    // Explicit code islands exclude literal pools; ends are exclusive.
    private static final long[][][] RANGES = {
        {{0x0e323488L, 0x0e3234b8L}},
        {{0x0e339258L, 0x0e33926aL}},
        {{0x0e339a88L, 0x0e339a90L}},
        {{0x0e33b8e8L, 0x0e33b8f6L}},
        {{0x0e33b898L, 0x0e33b8a6L}},
        {{0x0e13ffb8L, 0x0e140014L}},
        {{0x0e1459f2L, 0x0e145a4cL}},
        {{0x0e14594eL, 0x0e145958L}},
        {{0x0e286bccL, 0x0e286c10L}},
        {{0x0e32e2ecL, 0x0e32e326L}},
        {{0x0e286d7eL, 0x0e286e0eL}},
        {{0x0e2807f8L, 0x0e280856L}},
        {{0x0e280734L, 0x0e2807f8L}},
        {{0x0e10678cL, 0x0e1067c4L}},
        {{0x0e27f198L, 0x0e27f26aL}},
        {{0x0e27f166L, 0x0e27f198L}},
        {{0x0e27dc5cL, 0x0e27dcc2L}},
        {{0x0e32dcf8L, 0x0e32dd54L}},
        {{0x0e27e12aL, 0x0e27e18eL}},
        {{0x0e345ebaL, 0x0e345ecaL}}
    };
    private static final String[] NAMES = {
        "probe_context_global_select",
        "probe_context_root_global",
        "probe_global_associated_adapter",
        "probe_global_associated_get",
        "probe_global_backing_get",
        "probe_associated_construct",
        "probe_frame_associated_get",
        "probe_frame_script_state_get",
        "probe_script_state_construct",
        "probe_script_wrapper_lazy_get",
        "probe_script_wrapper_initialize",
        "probe_script_wrapper_construct",
        "probe_script_global_create_install",
        "probe_script_global_entry",
        "probe_script_global_construct",
        "probe_script_global_backing_construct",
        "probe_script_global_base_construct",
        "probe_script_wrapper_global_install",
        "probe_script_backing_base_construct",
        "probe_associated_pointer_retain"
    };

    @Override
    public void run() throws Exception {
        String expected = "44823cc35a80acb383241589c45a2f57b808d40cb7a265fb60a0a941eedc6511";
        if (!expected.equalsIgnoreCase(currentProgram.getExecutableSHA256())) {
            throw new IllegalArgumentException("Probe requires the documented ShpApp ELF digest");
        }
        if (getScriptArgs().length != 1) {
            throw new IllegalArgumentException("Supply one absolute local JSON output path");
        }
        Path destination = Path.of(getScriptArgs()[0]);
        if (!destination.isAbsolute() || Files.exists(destination)) {
            throw new IllegalArgumentException("Output must be absolute and absent");
        }
        Register thumb = currentProgram.getRegister("TMode");
        if (thumb == null) throw new IllegalStateException("No ARM TMode register");
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("program", currentProgram.getName());
        report.put("sha256", currentProgram.getExecutableSHA256());
        report.put("language", currentProgram.getLanguageID().toString());
        report.put("scope", "Twenty analyst-bounded script-global/frame lookup functions; no whole-program analysis");
        report.put("limitations", List.of(
            "Analyst-selected ranges and names are inputs, not discovered function boundaries",
            "Loader language is not evidence of the physical CPU model",
            "External callees and indirect runtime targets remain unresolved",
            "Pseudocode types and signatures are inferred; no target execution",
            "This is an ordinary Ghidra report, not REA Evidence"));
        Map<String, String> words = new LinkedHashMap<>();
        long[][] expectedWords = {
            {0x0e140014L, 0xe5c87b0L},
            {0x0e2809e4L, 0xe5b3c34L},
            {0x0e2809e8L, 0xe5c86fcL},
            {0x0e2809ecL, 0xe5a5dacL},
            {0x0e106a2cL, 0xe593868L},
            {0x0e27f2fcL, 0xe5a1944L},
            {0x0e27f300L, 0xe5a1954L},
            {0x0e27e078L, 0xe591240L},
            {0x0e27e07cL, 0xe58f18cL},
            {0x0e27e080L, 0xe58e538L},
            {0x0e27e084L, 0xe5aa858L},
            {0x0e286fc0L, 0x0L},
            {0x0e286fc4L, 0x0L},
            {0x0e32e328L, 0xe5fb1bcL},
            {0x0e27e1c8L, 0xe5aa848L}
        };
        for (long[] word : expectedWords) {
            long actual = Integer.toUnsignedLong(getInt(toAddr(word[0])));
            if (actual != word[1]) throw new IllegalStateException("Unexpected script/frame word");
            words.put("0x" + Long.toHexString(word[0]), "0x" + Long.toHexString(actual));
        }
        report.put("verified_words", words);
        List<Object> functions = new ArrayList<>();
        report.put("functions", functions);
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException(decompiler.getLastMessage());
        }
        try {
            for (int i = 0; i < RANGES.length; i++) {
                monitor.checkCancelled();
                Address start = toAddr(RANGES[i][0][0]);
                AddressSet body = new AddressSet();
                List<Object> islands = new ArrayList<>();
                for (long[] range : RANGES[i]) {
                    body.addRange(toAddr(range[0]), toAddr(range[1] - 1));
                    islands.add(Map.of("start", "0x" + Long.toHexString(range[0]),
                        "end_exclusive", "0x" + Long.toHexString(range[1])));
                }
                Iterator<Function> overlapping = currentProgram.getFunctionManager().getFunctionsOverlapping(body);
                List<Address> oldEntries = new ArrayList<>();
                while (overlapping.hasNext()) oldEntries.add(overlapping.next().getEntryPoint());
                for (Address old : oldEntries) currentProgram.getFunctionManager().removeFunction(old);
                for (long[] range : RANGES[i]) {
                    Address first = toAddr(range[0]), last = toAddr(range[1] - 1);
                    clearListing(first, last);
                    currentProgram.getProgramContext().setValue(thumb, first, last, BigInteger.ONE);
                }
                for (long[] range : RANGES[i]) {
                    DisassembleCommand command = new DisassembleCommand(toAddr(range[0]), body, true);
                    if (!command.applyTo(currentProgram, monitor)) {
                        throw new IllegalStateException("Thumb disassembly failed at " + toAddr(range[0]));
                    }
                }
                Function function = currentProgram.getFunctionManager().createFunction(
                    NAMES[i], start, body, SourceType.USER_DEFINED);
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("entry", "0x" + start);
                row.put("islands", islands);
                row.put("analyst_label", NAMES[i]);
                List<String> instructions = new ArrayList<>();
                InstructionIterator iterator = currentProgram.getListing().getInstructions(body, true);
                while (iterator.hasNext()) {
                    Instruction instruction = iterator.next();
                    instructions.add("0x" + instruction.getAddress() + ": " + instruction);
                }
                row.put("instructions", instructions);
                decompiler.flushCache();
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                row.put("decompile_completed", result.decompileCompleted());
                row.put("decompile_message", result.getErrorMessage());
                if (result.decompileCompleted()) row.put("pseudocode", result.getDecompiledFunction().getC());
                functions.add(row);
                println("Probed " + start + " (" + instructions.size() + " instructions)");
            }
        } finally {
            decompiler.dispose();
        }
        Files.createDirectories(destination.getParent());
        Files.writeString(destination, new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n");
        println("Wrote " + destination);
    }
}
