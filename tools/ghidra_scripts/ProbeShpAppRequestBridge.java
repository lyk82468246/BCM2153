// Bounded request-provider selection and registered resource callback delivery; local report only.
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

public class ProbeShpAppRequestBridge extends GhidraScript {
    // Explicit code islands exclude literal pools; ends are exclusive.
    // Complete and string-find methods include shared return islands.
    // Register entry is a branch veneer; the adjacent remove function is separate.
    private static final long[][][] RANGES = {
        {{0x0e28b3aeL, 0x0e28b5b6L}},
        {{0x0e28b5b6L, 0x0e28b6b0L}},
        {{0x0e28b120L, 0x0e28b122L}, {0x0e28b0caL, 0x0e28b120L}},
        {{0x0e28b174L, 0x0e28b1a0L}},
        {{0x0e28b122L, 0x0e28b174L}},
        {{0x0e28b1c0L, 0x0e28b1dcL}},
        {{0x0e28b1dcL, 0x0e28b1f8L}},
        {{0x0e28b1f8L, 0x0e28b226L}},
        {{0x0e28b226L, 0x0e28b250L}},
        {{0x0e288070L, 0x0e2880b2L}},
        {{0x0e28810eL, 0x0e288314L}},
        {{0x0e288314L, 0x0e288390L}, {0x0e2883ccL, 0x0e28841cL}, {0x0e28841eL, 0x0e2884f8L}},
        {{0x0e2884f8L, 0x0e2885d0L}, {0x0e288416L, 0x0e28841aL}},
        {{0x0e2885d0L, 0x0e28864aL}},
        {{0x0e28b2e0L, 0x0e28b2f4L}},
        {{0x0e28b290L, 0x0e28b2a0L}},
        {{0x0e28b7b8L, 0x0e28b7d4L}},
        {{0x0e28b36cL, 0x0e28b37eL}},
        {{0x0e33e506L, 0x0e33e52cL}},
        {{0x0e1b66e8L, 0x0e1b67f4L}, {0x0e1b62e0L, 0x0e1b62e4L}},
        {{0x0e31c2e4L, 0x0e31c2eeL}},
        {{0x0e353fd2L, 0x0e353fe2L}}
    };
    private static final String[] NAMES = {
        "probe_request_bridge_select",
        "probe_request_bridge_start",
        "probe_request_callback_register",
        "probe_request_callback_find",
        "probe_request_callback_remove",
        "probe_request_callback_response_route",
        "probe_request_callback_data_route",
        "probe_request_callback_complete_route",
        "probe_request_callback_error_route",
        "probe_request_callback_construct",
        "probe_request_callback_response",
        "probe_request_callback_data",
        "probe_request_callback_complete",
        "probe_request_callback_error",
        "probe_request_shared_provider_construct",
        "probe_request_file_provider_construct",
        "probe_request_provider_base_construct",
        "probe_request_bridge_construct",
        "probe_request_string_prefix_test",
        "probe_request_string_find",
        "probe_request_callback_base_construct",
        "probe_request_pointer_construct"
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
        report.put("scope", "Twenty-two bounded request-provider/callback functions; no whole-program analysis");
        report.put("limitations", List.of(
            "Analyst-selected ranges and names are inputs, not discovered function boundaries",
            "Loader language is not evidence of the physical CPU model",
            "External callees and indirect runtime targets remain unresolved",
            "Pseudocode types and signatures are inferred; no target execution",
            "This is an ordinary Ghidra report, not REA Evidence"));
        Map<String, String> words = new LinkedHashMap<>();
        long[][] expectedWords = {
            {0x0e28b7acL, 0xe5fcab4L},
            {0x0e28b28cL, 0xe5fb1bcL},
            {0x0e2883b8L, 0xe58b658L},
            {0x0e28b2d8L, 0xe58a3e4L},
            {0x0e28b364L, 0xe58a434L},
            {0x0e28b9e8L, 0xe58c138L},
            {0x0e28b760L, 0xe58b218L},
            {0x0e58b664L, 0xe28810fL},
            {0x0e58b668L, 0xe288315L},
            {0x0e58b66cL, 0xe2884f9L},
            {0x0e58b670L, 0xe2885d1L},
            {0x0e58a3e4L, 0xe28b8dbL},
            {0x0e58a434L, 0xe28b327L},
            {0x0e5ac41cL, 0xe16d13dL},
            {0x0e5ac420L, 0xe16d205L},
            {0x0e5ac424L, 0xe16d259L},
            {0x0e5ac428L, 0xe16d2abL}
        };
        for (long[] word : expectedWords) {
            long actual = Integer.toUnsignedLong(getInt(toAddr(word[0])));
            if (actual != word[1]) throw new IllegalStateException("Unexpected request bridge word");
            words.put("0x" + Long.toHexString(word[0]), "0x" + Long.toHexString(actual));
        }
        report.put("verified_words", words);
        Map<String, String> literals = Map.of(
            "0x0e28b768", "http",
            "0x0e28b770", "https",
            "0x0e28b778", "data",
            "0x0e28b780", "cid",
            "0x0e28b784", "about:blank",
            "0x0e28b790", "file",
            "0x0e28b798", "/User/Br/SavedPage");
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
