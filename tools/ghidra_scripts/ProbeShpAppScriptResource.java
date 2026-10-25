// Bounded script resource construction, byte storage and client notification; report stays local.
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

public class ProbeShpAppScriptResource extends GhidraScript {
    // Explicit code islands exclude literal pools; ends are exclusive.
    private static final long[][][] RANGES = {
        {{0x0e15b6deL, 0x0e15b6eeL}},
        {{0x0e3120e0L, 0x0e3120f8L}},
        {{0x0e15b714L, 0x0e15b726L}},
        {{0x0e15e130L, 0x0e15e1a2L}},
        {{0x0e15d668L, 0x0e15d75cL}},
        {{0x0e15e2d8L, 0x0e15e2fcL}},
        {{0x0e15d86eL, 0x0e15d8daL}},
        {{0x0e15e388L, 0x0e15e3daL}},
        {{0x0e15e33eL, 0x0e15e388L}},
        {{0x0e15e3daL, 0x0e15e3eaL}},
        {{0x0e15e24aL, 0x0e15e2d8L}},
        {{0x0e32782cL, 0x0e3278a6L}},
        {{0x0e33d286L, 0x0e33d294L}},
        {{0x0e33d278L, 0x0e33d286L}},
        {{0x0e15b6bcL, 0x0e15b6deL}},
        {{0x0e15b652L, 0x0e15b6bcL}},
        {{0x0e15b60aL, 0x0e15b652L}},
        {{0x0e32bd98L, 0x0e32bda8L}},
        {{0x0e15d842L, 0x0e15d86eL}, {0x0e15d758L, 0x0e15d75cL}},
        {{0x0e15dba6L, 0x0e15dbf6L}},
        {{0x0e15dfb4L, 0x0e15e072L}},
        {{0x0e15e072L, 0x0e15e0a4L}},
        {{0x0e3ac504L, 0x0e3ac51aL}},
        {{0x0e32bd68L, 0x0e32bd94L}}
    };
    private static final String[] NAMES = {
        "probe_resource_factory_prefix",
        "probe_resource_switch_helper_arm",
        "probe_resource_class2_factory_case",
        "probe_script_resource_construct",
        "probe_resource_base_construct",
        "probe_script_resource_client_attach",
        "probe_resource_client_attach_base",
        "probe_script_resource_bytes_accept",
        "probe_script_resource_clients_notify",
        "probe_script_resource_error",
        "probe_script_resource_text_get",
        "probe_cached_script_input_construct",
        "probe_cached_script_source_length",
        "probe_cached_script_source_data",
        "probe_resource_cache_touch",
        "probe_resource_cache_unlink",
        "probe_resource_cache_link",
        "probe_resource_start_adapter",
        "probe_resource_start",
        "probe_resource_byte_length_set",
        "probe_resource_client_snapshot",
        "probe_resource_client_snapshot_next",
        "probe_cached_source_resource_set",
        "probe_resource_reference_retain"
    };
    private static final int ARM_HELPER_INDEX = 1;

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
        report.put("scope", "Twenty-two bounded resource functions and two disassembly-only factory slices; one explicit ARM switch helper; no whole-program analysis");
        report.put("limitations", List.of(
            "Analyst-selected ranges and names are inputs, not discovered function boundaries",
            "Factory prefix/case are partial slices; switch routing must be checked from ARM helper and inline bytes, not their pseudocode",
            "Loader language is not evidence of the physical CPU model",
            "External callees and indirect runtime targets remain unresolved",
            "Pseudocode types and signatures are inferred; no target execution",
            "This is an ordinary Ghidra report, not REA Evidence"));
        Map<String, String> words = new LinkedHashMap<>();
        long[][] expectedWords = {
            {0x0e15b6eeL, 0x130c0405L},
            {0x0e15b6f2L, 0x2b251cL},
            {0x0e3120e0L, 0xe55ec001L},
            {0x0e3120f4L, 0xe12fff1cL},
            {0x0e15e4e4L, 0xe595514L},
            {0x0e59551cL, 0xe32bd99L},
            {0x0e595528L, 0xe15e389L},
            {0x0e59552cL, 0xe15e3dbL},
            {0x0e595530L, 0xe15e2d9L},
            {0x0e1f9854L, 0xe5ac2d4L},
            {0x0e5ac2f0L, 0xe1f97e3L},
            {0x0e3278a8L, 0xe5bcbb8L},
            {0x0e5bcbc4L, 0xe33d279L},
            {0x0e5bcbc8L, 0xe33d287L}
        };
        for (long[] word : expectedWords) {
            long actual = Integer.toUnsignedLong(getInt(toAddr(word[0])));
            if (actual != word[1]) throw new IllegalStateException("Unexpected script resource word");
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
                    currentProgram.getProgramContext().setValue(thumb, first, last, i == ARM_HELPER_INDEX ? BigInteger.ZERO : BigInteger.ONE);
                }
                for (long[] range : RANGES[i]) {
                    DisassembleCommand command = new DisassembleCommand(toAddr(range[0]), body, true);
                    if (!command.applyTo(currentProgram, monitor)) {
                        throw new IllegalStateException("Disassembly failed at " + toAddr(range[0]));
                    }
                }
                Function function = currentProgram.getFunctionManager().createFunction(
                    NAMES[i], start, body, SourceType.USER_DEFINED);
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("entry", "0x" + start);
                row.put("instruction_set", i == ARM_HELPER_INDEX ? "ARM" : "Thumb");
                row.put("islands", islands);
                row.put("analyst_label", NAMES[i]);
                List<String> instructions = new ArrayList<>();
                InstructionIterator iterator = currentProgram.getListing().getInstructions(body, true);
                while (iterator.hasNext()) {
                    Instruction instruction = iterator.next();
                    instructions.add("0x" + instruction.getAddress() + ": " + instruction);
                }
                row.put("instructions", instructions);
                if (i == 0 || i == 2) {
                    row.put("decompile_skipped", "Partial factory slice; use instruction flow, inline switch bytes and explicit ARM helper");
                } else {
                    decompiler.flushCache();
                    DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                    row.put("decompile_completed", result.decompileCompleted());
                    row.put("decompile_message", result.getErrorMessage());
                    if (result.decompileCompleted()) row.put("pseudocode", result.getDecompiledFunction().getC());
                }
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
