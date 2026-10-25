// Bounded transfer byte storage and queue delivery to resource acceptance; local report only.
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

public class ProbeShpAppTransferDelivery extends GhidraScript {
    // Explicit code islands exclude literal pools; ends are exclusive.
    // Transfer-data, queue-data and queue-complete include shared return islands.
    private static final long[][][] RANGES = {
        {{0x0e16d13cL, 0x0e16d204L}},
        {{0x0e16d204L, 0x0e16d258L}, {0x0e16d18eL, 0x0e16d192L}},
        {{0x0e16d258L, 0x0e16d2aaL}},
        {{0x0e16d2aaL, 0x0e16d30aL}},
        {{0x0e16c910L, 0x0e16c95aL}},
        {{0x0e16c95aL, 0x0e16c9a8L}},
        {{0x0e16c9d2L, 0x0e16ca00L}},
        {{0x0e16ca00L, 0x0e16ca1eL}},
        {{0x0e16ca1eL, 0x0e16ca72L}},
        {{0x0e16c792L, 0x0e16c83aL}},
        {{0x0e16c844L, 0x0e16c890L}},
        {{0x0e32aefaL, 0x0e32af1cL}},
        {{0x0e0166d8L, 0x0e01671aL}},
        {{0x0e01678aL, 0x0e0167beL}},
        {{0x0e0167beL, 0x0e0167f0L}},
        {{0x0e0167f0L, 0x0e01681cL}},
        {{0x0e16a7b0L, 0x0e16a8e2L}},
        {{0x0e16a8e2L, 0x0e16a99aL}, {0x0e16a798L, 0x0e16a79cL}},
        {{0x0e16a99aL, 0x0e16aa7cL}, {0x0e16a3a6L, 0x0e16a3aaL}},
        {{0x0e16aa7cL, 0x0e16aa86L}},
        {{0x0e16a368L, 0x0e16a45cL}},
        {{0x0e3b14eaL, 0x0e3b14feL}},
        {{0x0e16cb9aL, 0x0e16cc48L}}
    };
    private static final String[] NAMES = {
        "probe_transfer_response",
        "probe_transfer_data",
        "probe_transfer_complete",
        "probe_transfer_error",
        "probe_transfer_base_response",
        "probe_transfer_base_data",
        "probe_transfer_base_finish",
        "probe_transfer_base_complete",
        "probe_transfer_base_error",
        "probe_transfer_buffer_store",
        "probe_transfer_buffer_get",
        "probe_byte_buffer_create",
        "probe_byte_buffer_construct",
        "probe_byte_buffer_data",
        "probe_byte_buffer_length",
        "probe_byte_buffer_append",
        "probe_queue_response",
        "probe_queue_data",
        "probe_queue_complete",
        "probe_queue_error",
        "probe_queue_error_remove",
        "probe_transfer_job_lookup",
        "probe_transfer_base_construct"
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
        report.put("scope", "Twenty-three bounded transfer/buffer/queue-delivery functions; no whole-program analysis");
        report.put("limitations", List.of(
            "Analyst-selected ranges and names are inputs, not discovered function boundaries",
            "Loader language is not evidence of the physical CPU model",
            "External callees and indirect runtime targets remain unresolved",
            "Pseudocode types and signatures are inferred; no target execution",
            "This is an ordinary Ghidra report, not REA Evidence"));
        Map<String, String> words = new LinkedHashMap<>();
        long[][] expectedWords = {
            {0x0e16c840L, 0xe5fb1bcL},
            {0x0e16d0e8L, 0xe5ac3b4L},
            {0x0e16a07cL, 0xe5c74d4L},
            {0x0e5ac40cL, 0xe16c793L},
            {0x0e5ac410L, 0xe16c845L},
            {0x0e5ac41cL, 0xe16d13dL},
            {0x0e5ac420L, 0xe16d205L},
            {0x0e5ac424L, 0xe16d259L},
            {0x0e5ac428L, 0xe16d2abL},
            {0x0e5c74e4L, 0xe16a7b1L},
            {0x0e5c74e8L, 0xe16a8e3L},
            {0x0e5c74ecL, 0xe16a99bL},
            {0x0e5c74f0L, 0xe16aa7dL},
            {0x0e595528L, 0xe15e389L},
            {0x0e59552cL, 0xe15e3dbL},
            {0x0e59551cL, 0xe32bd99L}
        };
        for (long[] word : expectedWords) {
            long actual = Integer.toUnsignedLong(getInt(toAddr(word[0])));
            if (actual != word[1]) throw new IllegalStateException("Unexpected transfer delivery word");
            words.put("0x" + Long.toHexString(word[0]), "0x" + Long.toHexString(actual));
        }
        report.put("verified_words", words);
        Map<String, String> literals = Map.of(
            "0x0e16d400", "multipart/x-mixed-replace",
            "0x0e16aaa0", "multipart/x-mixed-replace");
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
