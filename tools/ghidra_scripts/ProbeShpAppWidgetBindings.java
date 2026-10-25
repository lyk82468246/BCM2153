// Bounded WidgetObject callback analysis in a read-only ShpApp project; report stays local.
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

public class ProbeShpAppWidgetBindings extends GhidraScript {
    // End addresses are exclusive, verified independently with ARM objdump.
    private static final long[][] RANGES = {
        {0x0e0ed93cL, 0x0e0ed996L}, {0x0e0eda30L, 0x0e0eda86L},
        {0x0e0edadeL, 0x0e0edbacL}, {0x0e14593cL, 0x0e145942L},
        {0x0e338aecL, 0x0e338b00L}, {0x0e338db4L, 0x0e338decL}
    };
    private static final String[] NAMES = {
        "probe_widget_resizeWindow", "probe_widget_getCurrentDirection",
        "probe_widget_addEventListener", "probe_widget_native_bridge",
        "probe_widget_argument_at", "probe_widget_integer_conversion"
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
        report.put("scope", "Six analyst-bounded WidgetObject callbacks/helpers plus ten name-pointer records; no whole-program analysis");
        report.put("limitations", List.of(
            "Analyst-selected ranges and names are inputs, not discovered function boundaries",
            "Loader language is not evidence of the physical CPU model",
            "External callees and indirect runtime targets remain unresolved",
            "Pseudocode types and signatures are inferred; no target execution",
            "This is an ordinary Ghidra report, not REA Evidence"));
        List<Object> bindings = new ArrayList<>();
        report.put("binding_records", bindings);
        // Ten 16-byte records; field semantics beyond name/callback are unknown.
        for (long at = 0x0e532754L; at < 0x0e5327f4L; at += 16) {
            Map<String, Object> binding = new LinkedHashMap<>();
            binding.put("record_vma", "0x" + Long.toHexString(at));
            long nameAddress = Integer.toUnsignedLong(getInt(toAddr(at)));
            binding.put("name_vma", "0x" + Long.toHexString(nameAddress));
            StringBuilder name = new StringBuilder();
            boolean terminated = false;
            for (int n = 0; n < 64; n++) {
                int value = Byte.toUnsignedInt(getByte(toAddr(nameAddress + n)));
                if (value == 0) { terminated = true; break; }
                if (value < 32 || value > 126) throw new IllegalStateException("Non-ASCII binding name");
                name.append((char)value);
            }
            if (!terminated) throw new IllegalStateException("Unterminated binding name");
            binding.put("name", name.toString());
            binding.put("word_4", Integer.toUnsignedLong(getInt(toAddr(at + 4))));
            binding.put("callback_pointer", "0x" + Long.toHexString(Integer.toUnsignedLong(getInt(toAddr(at + 8)))));
            binding.put("word_c", Integer.toUnsignedLong(getInt(toAddr(at + 12))));
            bindings.add(binding);
        }
        List<Object> functions = new ArrayList<>();
        report.put("functions", functions);
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException(decompiler.getLastMessage());
        }
        try {
            for (int i = 0; i < RANGES.length; i++) {
                monitor.checkCancelled();
                Address start = toAddr(RANGES[i][0]), last = toAddr(RANGES[i][1] - 1);
                AddressSet body = new AddressSet(start, last);
                Iterator<Function> overlapping = currentProgram.getFunctionManager().getFunctionsOverlapping(body);
                List<Address> oldEntries = new ArrayList<>();
                while (overlapping.hasNext()) oldEntries.add(overlapping.next().getEntryPoint());
                for (Address old : oldEntries) currentProgram.getFunctionManager().removeFunction(old);
                clearListing(start, last);
                currentProgram.getProgramContext().setValue(thumb, start, last, BigInteger.ONE);
                DisassembleCommand command = new DisassembleCommand(start, body, true);
                if (!command.applyTo(currentProgram, monitor)) {
                    throw new IllegalStateException("Thumb disassembly failed at " + start);
                }
                Function function = currentProgram.getFunctionManager().createFunction(
                    NAMES[i], start, body, SourceType.USER_DEFINED);
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("entry", "0x" + start);
                row.put("end_exclusive", "0x" + toAddr(RANGES[i][1]));
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
