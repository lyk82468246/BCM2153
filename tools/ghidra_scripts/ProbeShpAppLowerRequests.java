// Bounded lower request construction, adjusted provider interfaces and callback routing; local report only.
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

public class ProbeShpAppLowerRequests extends GhidraScript {
    // Explicit code islands exclude literal pools; ends are exclusive.
    private static final long[][][] RANGES = {
        {{0x0e28b326L, 0x0e28b32eL}},
        {{0x0e28b8daL, 0x0e28b90cL}},
        {{0x0e28b890L, 0x0e28b8daL}},
        {{0x0e28b862L, 0x0e28b890L}},
        {{0x0e28b34aL, 0x0e28b364L}},
        {{0x0e28b2beL, 0x0e28b2d8L}},
        {{0x0e288dd4L, 0x0e288de4L}},
        {{0x0e288ce0L, 0x0e288cf0L}},
        {{0x0e28aea8L, 0x0e28af12L}},
        {{0x0e28af8eL, 0x0e28af94L}},
        {{0x0e288fdcL, 0x0e288ff6L}},
        {{0x0e288db6L, 0x0e288dc8L}},
        {{0x0e28b952L, 0x0e28b95cL}},
        {{0x0e28b960L, 0x0e28b96aL}},
        {{0x0e28b96eL, 0x0e28b9a2L}},
        {{0x0e28b9a6L, 0x0e28b9dcL}},
        {{0x0e28b32eL, 0x0e28b336L}},
        {{0x0e28b336L, 0x0e28b33aL}},
        {{0x0e28b95cL, 0x0e28b960L}},
        {{0x0e28b96aL, 0x0e28b96eL}},
        {{0x0e28b9a2L, 0x0e28b9a6L}},
        {{0x0e28b9dcL, 0x0e28b9e0L}},
        {{0x0e28b9e0L, 0x0e28b9e2L}},
        {{0x0e28b9e2L, 0x0e28b9e6L}},
        {{0x0e28afcaL, 0x0e28affeL}},
        {{0x0e28affeL, 0x0e28b004L}},
        {{0x0e28b004L, 0x0e28b016L}},
        {{0x0e28b016L, 0x0e28b01eL}},
        {{0x0e28b01eL, 0x0e28b028L}},
        {{0x0e28b028L, 0x0e28b03cL}},
        {{0x0e28afc0L, 0x0e28afcaL}},
        {{0x0e288980L, 0x0e2889deL}},
        {{0x0e28b048L, 0x0e28b05eL}},
        {{0x0e28bed4L, 0x0e28bee4L}}
    };
    private static final String[] NAMES = {
        "probe_lower_shared_start",
        "probe_lower_provider_start",
        "probe_lower_request_add",
        "probe_lower_request_remove",
        "probe_lower_shared_request_create",
        "probe_lower_file_request_create",
        "probe_lower_shared_request_construct",
        "probe_lower_file_request_construct",
        "probe_lower_request_base_construct",
        "probe_lower_request_start_dispatch",
        "probe_lower_shared_request_start",
        "probe_lower_file_request_start",
        "probe_lower_provider_response",
        "probe_lower_provider_data",
        "probe_lower_provider_complete",
        "probe_lower_provider_error",
        "probe_lower_shared_response_bridge",
        "probe_lower_shared_response_adjust",
        "probe_lower_file_response_adjust",
        "probe_lower_data_adjust",
        "probe_lower_complete_adjust",
        "probe_lower_error_adjust",
        "probe_lower_provider_identity",
        "probe_lower_provider_identity_adjust",
        "probe_lower_request_notify",
        "probe_lower_request_complete",
        "probe_lower_request_error",
        "probe_lower_request_data",
        "probe_lower_request_set_data",
        "probe_lower_request_prepare_data",
        "probe_lower_request_take_data",
        "probe_frame_request_helper_construct",
        "probe_request_registry_construct",
        "probe_lower_data_description_construct"
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
        report.put("scope", "34 bounded lower-request/provider-interface functions; no whole-program analysis");
        report.put("limitations", List.of(
            "Analyst-selected ranges and names are inputs, not discovered function boundaries",
            "Loader language is not evidence of the physical CPU model",
            "External callees and indirect runtime targets remain unresolved",
            "Pseudocode types and signatures are inferred; no target execution",
            "This is an ordinary Ghidra report, not REA Evidence"));
        Map<String, String> words = new LinkedHashMap<>();
        long[][] expectedWords = {
            {0x0e288dc8L, 0xe58abecL},
            {0x0e289010L, 0xe58ac6cL},
            {0x0e28b2d8L, 0xe58a3e4L},
            {0x0e28b364L, 0xe58a434L},
            {0x0e28b2dcL, 0xe5fb1bcL},
            {0x0e28b368L, 0xe5fb1bcL},
            {0x0e28b03cL, 0xe58abacL},
            {0x0e58a40cL, 0xe28b2bfL},
            {0x0e58a418L, 0xe28b95dL},
            {0x0e58a41cL, 0xe28b96bL},
            {0x0e58a420L, 0xe28b9a3L},
            {0x0e58a424L, 0xe28b9ddL},
            {0x0e58a428L, 0xe28b9e3L},
            {0x0e58a45cL, 0xe28b34bL},
            {0x0e58a468L, 0xe28b337L},
            {0x0e58a46cL, 0xe28b96bL},
            {0x0e58a470L, 0xe28b9a3L},
            {0x0e58a474L, 0xe28b9ddL},
            {0x0e58a478L, 0xe28b9e3L},
            {0x0e58abf4L, 0xe28af8fL},
            {0x0e58ac18L, 0xe288db7L},
            {0x0e58ac1cL, 0xe28b017L},
            {0x0e58ac20L, 0xe28b029L},
            {0x0e58ac74L, 0xe28af8fL},
            {0x0e58ac98L, 0xe288fddL},
            {0x0e58ac9cL, 0xe28b017L},
            {0x0e58aca0L, 0xe28b029L},
            {0x0e288cc4L, 0xe58a7a0L},
            {0x0e28b288L, 0xe58b208L},
            {0x0e28bf14L, 0xe58af98L}
        };
        for (long[] word : expectedWords) {
            long actual = Integer.toUnsignedLong(getInt(toAddr(word[0])));
            if (actual != word[1]) throw new IllegalStateException("Unexpected lower request word");
            words.put("0x" + Long.toHexString(word[0]), "0x" + Long.toHexString(actual));
        }
        report.put("verified_words", words);
        Map<String, String> literals = Map.of("0x0e28b044", "#");
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
