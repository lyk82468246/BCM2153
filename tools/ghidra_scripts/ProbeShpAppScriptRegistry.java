// Bounded HTML name initialization and script interface attribute lookup; read-only report stays local.
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

public class ProbeShpAppScriptRegistry extends GhidraScript {
    // Explicit code islands exclude literal pools; ends are exclusive.
    private static final long[][][] RANGES = {
        {{0x0e12cb00L, 0x0e12cdf0L}, {0x0e12d0dcL, 0x0e12d4d8L}, {0x0e12d4dcL, 0x0e12d8d0L}, {0x0e12d8d4L, 0x0e12dcd8L}, {0x0e12ded4L, 0x0e12e07cL}, {0x0e12e470L, 0x0e12e6c8L}, {0x0e12e97cL, 0x0e12ed88L}, {0x0e12ed90L, 0x0e12f19eL}, {0x0e12f1a4L, 0x0e12f598L}, {0x0e12f59cL, 0x0e12f990L}, {0x0e12f994L, 0x0e12fd88L}, {0x0e12fd8cL, 0x0e13006cL}},
        {{0x0e1f66deL, 0x0e1f674eL}},
        {{0x0e32a646L, 0x0e32a664L}},
        {{0x0e21b750L, 0x0e21b776L}},
        {{0x0e21be66L, 0x0e21be6aL}, {0x0e21be50L, 0x0e21be66L}},
        {{0x0e21be80L, 0x0e21be84L}, {0x0e21be6aL, 0x0e21be80L}},
        {{0x0e21be9aL, 0x0e21be9eL}, {0x0e21be84L, 0x0e21be9aL}},
        {{0x0e21beb4L, 0x0e21beb8L}, {0x0e21be9eL, 0x0e21beb4L}}
    };
    private static final String[] NAMES = {
        "probe_html_names_initialize",
        "probe_qualified_name_intern",
        "probe_ascii_name_construct",
        "probe_script_owner_construct",
        "probe_script_source_attribute_get",
        "probe_script_charset_attribute_get",
        "probe_script_type_attribute_get",
        "probe_script_language_attribute_get"
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
        report.put("scope", "Eight analyst-bounded HTML name initialization/interface functions; no whole-program analysis");
        report.put("limitations", List.of(
            "Analyst-selected ranges and names are inputs, not discovered function boundaries",
            "Loader language is not evidence of the physical CPU model",
            "External callees and indirect runtime targets remain unresolved",
            "Pseudocode types and signatures are inferred; no target execution",
            "This is an ordinary Ghidra report, not REA Evidence"));
        Map<String, String> words = new LinkedHashMap<>();
        long[][] expectedWords = {
            {0x0e12cdf8L, 0xe5fb280L},
            {0x0e12d0d8L, 0xe5fc3acL},
            {0x0e12d4d8L, 0xe5fc3acL},
            {0x0e12dcd8L, 0xe5fc3acL},
            {0x0e12e974L, 0xe5fb428L},
            {0x0e12e904L, 0xe12e080L},
            {0x0e21bb48L, 0xe5fb3c8L},
            {0x0e21bb50L, 0xe5aa318L},
            {0x0e21bf08L, 0xe5fb4bcL},
            {0x0e21bf10L, 0xe5fb72cL},
            {0x0e21bf14L, 0xe5fb760L},
            {0x0e21bf18L, 0xe5fb58cL},
            {0x0e5aa368L, 0xe21be81L},
            {0x0e5aa364L, 0xe21be67L},
            {0x0e5aa36cL, 0xe21be9bL},
            {0x0e5aa370L, 0xe21beb5L}
        };
        for (long[] word : expectedWords) {
            long actual = Integer.toUnsignedLong(getInt(toAddr(word[0])));
            if (actual != word[1]) throw new IllegalStateException("Unexpected HTML name/interface word");
            words.put("0x" + Long.toHexString(word[0]), "0x" + Long.toHexString(actual));
        }
        report.put("verified_words", words);
        Map<String, String> literals = Map.of(
            "0x0e12d040", "script",
            "0x0e12dea0", "charset",
            "0x0e12e080", "type",
            "0x0e12e1f0", "language",
            "0x0e12e8a4", "src",
            "0x0e12cdfc", "http://www.w3.org/1999/xhtml");
        for (Map.Entry<String, String> literal : literals.entrySet()) {
            byte[] expectedBytes = (literal.getValue() + "\0").getBytes(
                java.nio.charset.StandardCharsets.US_ASCII);
            byte[] actual = getBytes(toAddr(Long.decode(literal.getKey())), expectedBytes.length);
            if (!java.util.Arrays.equals(actual, expectedBytes)) {
                throw new IllegalStateException("Unexpected HTML name literal");
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
