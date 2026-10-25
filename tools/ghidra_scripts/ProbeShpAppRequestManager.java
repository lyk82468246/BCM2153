// Bounded request manager submission, pending queue and acquisition handoff; local report only.
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

public class ProbeShpAppRequestManager extends GhidraScript {
    // Explicit code islands exclude literal pools; ends are exclusive.
    private static final long[][][] RANGES = {
        {{0x0e289d2eL, 0x0e289d62L}},
        {{0x0e289d62L, 0x0e289d8cL}},
        {{0x0e28a892L, 0x0e28a942L}},
        {{0x0e28a4eaL, 0x0e28a78eL}, {0x0e28a882L, 0x0e28a892L}},
        {{0x0e28a96aL, 0x0e28a9b2L}},
        {{0x0e28a9b2L, 0x0e28a9ceL}},
        {{0x0e28a942L, 0x0e28a96aL}},
        {{0x0e28a9eaL, 0x0e28aa28L}},
        {{0x0e28aa28L, 0x0e28aa56L}},
        {{0x0e28aa56L, 0x0e28aa62L}},
        {{0x0e337f32L, 0x0e337f36L}},
        {{0x0e337f36L, 0x0e337f3aL}},
        {{0x0e337f3aL, 0x0e337f3eL}}
    };
    private static final String[] NAMES = {
        "probe_request_manager_construct",
        "probe_request_manager_get",
        "probe_request_manager_submit",
        "probe_request_manager_acquire",
        "probe_request_manager_remove_pending",
        "probe_request_manager_cancel_pending",
        "probe_request_manager_cancel_started",
        "probe_request_manager_process_pending",
        "probe_request_manager_timer",
        "probe_request_manager_control_get",
        "probe_request_data_description_length",
        "probe_request_data_description_response",
        "probe_request_data_description_pointer"
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
        report.put("scope", "Thirteen bounded request-manager/data-description functions; no whole-program analysis");
        report.put("limitations", List.of(
            "Analyst-selected ranges and names are inputs, not discovered function boundaries",
            "Loader language is not evidence of the physical CPU model",
            "External callees and indirect runtime targets remain unresolved",
            "Pseudocode types and signatures are inferred; no target execution",
            "This is an ordinary Ghidra report, not REA Evidence"));
        Map<String, String> words = new LinkedHashMap<>();
        long[][] expectedWords = {
            {0x0e289e70L, 0xe557ac4L},
            {0x0e289e74L, 0xe5c6b4cL},
            {0x0e289e80L, 0xe5fcab0L},
            {0x0e28aa80L, 0xe5fcab0L},
            {0x0e28aa8cL, 0xe289e78L},
            {0x0e28a7e4L, 0xe5fb1bcL},
            {0x0e28aa7cL, 0xe28a7dcL},
            {0x0e28a854L, 0xe289051L},
            {0x0e28a858L, 0xe2897c7L},
            {0x0e28a85cL, 0xe2896cdL},
            {0x0e28a860L, 0xe28944bL},
            {0x0e28a864L, 0xe289bc7L},
            {0x0e28a868L, 0xe289c19L},
            {0x0e28a86cL, 0xe289c33L},
            {0x0e28a870L, 0xe289779L},
            {0x0e28a874L, 0xe289affL},
            {0x0e28a878L, 0xe289b8bL},
            {0x0e28a87cL, 0xe289805L},
            {0x0e58af98L, 0xe337f3bL},
            {0x0e58af9cL, 0xe337f33L},
            {0x0e58afa0L, 0xe337f37L}
        };
        for (long[] word : expectedWords) {
            long actual = Integer.toUnsignedLong(getInt(toAddr(word[0])));
            if (actual != word[1]) throw new IllegalStateException("Unexpected request manager word");
            words.put("0x" + Long.toHexString(word[0]), "0x" + Long.toHexString(actual));
        }
        report.put("verified_words", words);
        Map<String, String> literals = Map.of(
            "0x0e28a7dc", "data");
        for (Map.Entry<String, String> literal : literals.entrySet()) {
            byte[] expectedBytes = (literal.getValue() + "\0").getBytes(
                java.nio.charset.StandardCharsets.US_ASCII);
            byte[] actual = getBytes(toAddr(Long.decode(literal.getKey())), expectedBytes.length);
            if (!java.util.Arrays.equals(actual, expectedBytes)) {
                throw new IllegalStateException("Unexpected resource request literal");
            }
        }
        report.put("verified_literals", literals);
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
                DecompileResults result = decompiler.decompileFunction(function, i == 0 ? 60 : 30, monitor);
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
