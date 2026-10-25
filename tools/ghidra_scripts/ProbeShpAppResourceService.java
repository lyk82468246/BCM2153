// Bounded resource loading queues, loader construction and frame-provider handoff; local report only.
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

public class ProbeShpAppResourceService extends GhidraScript {
    // Explicit code islands exclude literal pools; ends are exclusive.
    private static final long[][][] RANGES = {
        {{0x0e16a260L, 0x0e16a368L}},
        {{0x0e16c424L, 0x0e16c450L}},
        {{0x0e169c84L, 0x0e169cc2L}},
        {{0x0e169cc2L, 0x0e169d0eL}},
        {{0x0e16a1d8L, 0x0e16a206L}},
        {{0x0e16a206L, 0x0e16a22eL}},
        {{0x0e16a22eL, 0x0e16a232L}},
        {{0x0e16a232L, 0x0e16a260L}},
        {{0x0e169da2L, 0x0e16a07cL}, {0x0e16a118L, 0x0e16a14cL}, {0x0e16a14eL, 0x0e16a1d8L}},
        {{0x0e16cd26L, 0x0e16cfd4L}},
        {{0x0e16ccf0L, 0x0e16cd26L}},
        {{0x0e16cb9aL, 0x0e16cc48L}},
        {{0x0e16cffaL, 0x0e16d074L}},
        {{0x0e16c554L, 0x0e16c60cL}},
        {{0x0e14593cL, 0x0e145942L}},
        {{0x0e1e2f14L, 0x0e1e2f2aL}},
        {{0x0e1a685cL, 0x0e1a68acL}},
        {{0x0e15c3e8L, 0x0e15c458L}},
        {{0x0e1a2aecL, 0x0e1a2b06L}},
        {{0x0e288668L, 0x0e288682L}},
        {{0x0e2887d8L, 0x0e2888d8L}},
        {{0x0e288b4cL, 0x0e288bcaL}}
    };
    private static final String[] NAMES = {
        "probe_resource_service_enqueue",
        "probe_resource_job_construct",
        "probe_resource_queue_construct",
        "probe_resource_service_construct",
        "probe_resource_queue_dispatch",
        "probe_resource_queue_append",
        "probe_resource_job_priority",
        "probe_resource_queue_has_work",
        "probe_resource_queue_drain",
        "probe_resource_loader_create",
        "probe_resource_loader_construct",
        "probe_resource_loader_base_construct",
        "probe_resource_loader_start",
        "probe_resource_loader_base_start",
        "probe_frame_owner_get",
        "probe_document_frame_owner_get",
        "probe_resource_scheme_match",
        "probe_resource_manager_construct",
        "probe_frame_resource_bridge_construct",
        "probe_frame_provider_construct",
        "probe_frame_provider_start",
        "probe_frame_provider_dispatch"
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
        report.put("scope", "Twenty-two bounded resource queue/loader/provider-handoff functions; no whole-program analysis");
        report.put("limitations", List.of(
            "Analyst-selected ranges and names are inputs, not discovered function boundaries",
            "Loader language is not evidence of the physical CPU model",
            "External callees and indirect runtime targets remain unresolved",
            "Pseudocode types and signatures are inferred; no target execution",
            "This is an ordinary Ghidra report, not REA Evidence"));
        Map<String, String> words = new LinkedHashMap<>();
        long[][] expectedWords = {
            {0x0e16a57cL, 0xe16a0a0L},
            {0x0e16a580L, 0xe16a0a8L},
            {0x0e16a584L, 0x2710L},
            {0x0e16a07cL, 0xe5c74d4L},
            {0x0e16a084L, 0x2710L},
            {0x0e16a08cL, 0xe5c6d90L},
            {0x0e16a578L, 0xbbadbeefL},
            {0x0e16ccecL, 0xe59ebf4L},
            {0x0e16d0e8L, 0xe5ac3b4L},
            {0x0e5ac3f4L, 0xe16cffbL},
            {0x0e16d100L, 0xe5fb1bcL},
            {0x0e15c550L, 0xe15c170L},
            {0x0e1a2d78L, 0xe58a968L},
            {0x0e288938L, 0xe58a764L},
            {0x0e58a770L, 0xe2887d9L}
        };
        for (long[] word : expectedWords) {
            long actual = Integer.toUnsignedLong(getInt(toAddr(word[0])));
            if (actual != word[1]) throw new IllegalStateException("Unexpected script request word");
            words.put("0x" + Long.toHexString(word[0]), "0x" + Long.toHexString(actual));
        }
        report.put("verified_words", words);
        Map<String, String> literals = Map.of(
            "0x0e16a0a0", "http",
            "0x0e16a0a8", "https",
            "0x0e16d0f0", "file",
            "0x0e16d0f8", "Referer");
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
