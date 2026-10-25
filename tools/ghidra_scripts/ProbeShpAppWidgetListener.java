// Bounded Widget listener construction and callback-call analysis; read-only report stays local.
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

public class ProbeShpAppWidgetListener extends GhidraScript {
    // Each function is a set of [start,end) islands, selected with ARM objdump.
    // The script-call helper shares an epilogue before its own entry.
    private static final long[][][] RANGES = {
        {{0x0e27de4eL, 0x0e27de86L}}, {{0x0e27de86L, 0x0e27dee4L}},
        {{0x0e281442L, 0x0e2814a8L}}, {{0x0e331e0cL, 0x0e331e1eL}},
        {{0x0e281422L, 0x0e281426L}}, {{0x0e281426L, 0x0e28142aL}},
        {{0x0e280f08L, 0x0e2812d8L}}, {{0x0e280d92L, 0x0e280ef0L}},
        {{0x0e0dad48L, 0x0e0daddcL}},
        {{0x0e0e2102L, 0x0e0e215cL}, {0x0e0e20faL, 0x0e0e20feL}}
    };
    private static final String[] NAMES = {
        "probe_listener_cache_lookup", "probe_listener_factory",
        "probe_listener_construct", "probe_listener_base_construct",
        "probe_listener_callback_get", "probe_listener_context_get",
        "probe_listener_invoke", "probe_event_to_script_value",
        "probe_script_call_bridge", "probe_script_call_nonhost"
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
        report.put("scope", "Ten analyst-bounded listener/call functions; explicit shared epilogue; no whole-program analysis");
        report.put("limitations", List.of(
            "Analyst-selected ranges and names are inputs, not discovered function boundaries",
            "Loader language is not evidence of the physical CPU model",
            "External callees and indirect runtime targets remain unresolved",
            "Pseudocode types and signatures are inferred; no target execution",
            "This is an ordinary Ghidra report, not REA Evidence"));
        long table = Integer.toUnsignedLong(getInt(toAddr(0x0e2816e8L)));
        if (table != 0x0e5a1a24L) throw new IllegalStateException("Unexpected listener table");
        Map<String, Object> vtable = new LinkedHashMap<>();
        vtable.put("literal_address", "0x0e2816e8");
        vtable.put("address", "0x" + Long.toHexString(table));
        List<String> slots = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            slots.add("0x" + Integer.toUnsignedString(getInt(toAddr(table + 4L * i)), 16));
        }
        vtable.put("seven_raw_words", slots);
        report.put("constructed_listener_vtable", vtable);
        byte[] literal = getBytes(toAddr(0x0e2812dcL), 12);
        if (!java.util.Arrays.equals(literal, new byte[] {
                'h', 'a', 'n', 'd', 'l', 'e', 'E', 'v', 'e', 'n', 't', 0})) {
            throw new IllegalStateException("Unexpected handleEvent literal");
        }
        report.put("property_literal", Map.of("address", "0x0e2812dc", "ascii", "handleEvent"));
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
