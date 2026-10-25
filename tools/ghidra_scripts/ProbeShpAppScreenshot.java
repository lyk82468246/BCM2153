// Bounded screenshot bitmap/encoder adapter analysis; report stays local.
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

public class ProbeShpAppScreenshot extends GhidraScript {
    // Two code islands of one Thumb function; intervening bytes are strings/pools.
    private static final long[][] RANGES = {
        {0x0e00069aL, 0x0e000824L}, {0x0e000924L, 0x0e000986L}
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
        report.put("scope", "One analyst-bounded Thumb screenshot adapter function; two code islands; no whole-program analysis");
        report.put("limitations", List.of(
            "Analyst-selected ranges and names are inputs, not discovered function boundaries",
            "Loader language is not evidence of the physical CPU model",
            "External callees and indirect runtime targets remain unresolved",
            "Pseudocode types and signatures are inferred; no target execution",
            "This is an ordinary Ghidra report, not REA Evidence"));
        List<Object> functions = new ArrayList<>();
        report.put("functions", functions);
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException(decompiler.getLastMessage());
        }
        try {
            AddressSet body = new AddressSet();
            for (int i = 0; i < RANGES.length; i++) {
                monitor.checkCancelled();
                Address start = toAddr(RANGES[i][0]), last = toAddr(RANGES[i][1] - 1);
                AddressSet island = new AddressSet(start, last);
                body.add(island);
                Iterator<Function> overlapping = currentProgram.getFunctionManager().getFunctionsOverlapping(island);
                List<Address> oldEntries = new ArrayList<>();
                while (overlapping.hasNext()) oldEntries.add(overlapping.next().getEntryPoint());
                for (Address old : oldEntries) currentProgram.getFunctionManager().removeFunction(old);
                clearListing(start, last);
                currentProgram.getProgramContext().setValue(thumb, start, last, BigInteger.ONE);
                DisassembleCommand command = new DisassembleCommand(start, island, true);
                if (!command.applyTo(currentProgram, monitor)) {
                    throw new IllegalStateException("Thumb disassembly failed at " + start);
                }
            }
            Address start = toAddr(RANGES[0][0]);
            Function function = currentProgram.getFunctionManager().createFunction(
                "probe_screenshot_save_adapter", start, body, SourceType.USER_DEFINED);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("entry", "0x" + start);
            row.put("code_ranges_end_exclusive", RANGES);
            row.put("analyst_label", "probe_screenshot_save_adapter");
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
        } finally {
            decompiler.dispose();
        }
        Files.createDirectories(destination.getParent());
        Files.writeString(destination, new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n");
        println("Wrote " + destination);
    }
}
