// Bounded registered control factory and name-bridge ownership analysis; read-only report stays local.
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

public class ProbeShpAppControlFactory extends GhidraScript {
    // Explicit code islands exclude literal pools; ends are exclusive.
    private static final long[][][] RANGES = {
        {{0x0e28d790L, 0x0e28d824L}, {0x0e28d868L, 0x0e28d884L}},
        {{0x0e28ce98L, 0x0e28cf36L}},
        {{0x0e28cde4L, 0x0e28ce98L}},
        {{0x0e28cbdcL, 0x0e28cc72L}, {0x0e28ccdcL, 0x0e28cde4L}},
        {{0x0e28ca4cL, 0x0e28ca50L}},
        {{0x0e28c0aeL, 0x0e28c0b2L}}
    };
    private static final String[] NAMES = {
        "probe_registered_control_factory", "probe_named_control_create",
        "probe_control_base_construct", "probe_control_initialize",
        "probe_control_name_bridge_get", "probe_control_frame_get"
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
        report.put("scope", "Six analyst-bounded control factory/ownership functions; explicit islands; no whole-program analysis");
        report.put("limitations", List.of(
            "Analyst-selected ranges and names are inputs, not discovered function boundaries",
            "Loader language is not evidence of the physical CPU model",
            "External callees and indirect runtime targets remain unresolved",
            "Pseudocode types and signatures are inferred; no target execution",
            "This is an ordinary Ghidra report, not REA Evidence"));
        Map<String, String> words = new LinkedHashMap<>();
        long[][] expectedWords = {
            {0x0e00ac44L, 0x0e28d791L}, {0x0e28d0bcL, 0x0e58c1c0L},
            {0x0e58c1e0L, 0x0e28ca4dL}, {0x0e29295cL, 0x0e58c50cL},
            {0x0e58c634L, 0x0e2941ebL}
        };
        for (long[] word : expectedWords) {
            long actual = Integer.toUnsignedLong(getInt(toAddr(word[0])));
            if (actual != word[1]) throw new IllegalStateException("Unexpected factory/table word");
            words.put("0x" + Long.toHexString(word[0]), "0x" + Long.toHexString(actual));
        }
        report.put("verified_words", words);
        Map<String, String> literals = Map.of(
            "0x0e28d0c4", "Browser", "0x0e28d0cc", "Widget", "0x0e28d0d4", "Messenger");
        for (Map.Entry<String, String> literal : literals.entrySet()) {
            byte[] expectedBytes = (literal.getValue() + "\0").getBytes(
                java.nio.charset.StandardCharsets.US_ASCII);
            byte[] actual = getBytes(toAddr(Long.decode(literal.getKey())), expectedBytes.length);
            if (!java.util.Arrays.equals(actual, expectedBytes)) {
                throw new IllegalStateException("Unexpected control category literal");
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
