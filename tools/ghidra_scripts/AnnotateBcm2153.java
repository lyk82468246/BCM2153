// Ghidra post-import helper for BCM2153 raw binary images.
// @category BCM2153

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import java.util.ArrayList;
import java.util.List;

public class AnnotateBcm2153 extends GhidraScript {
    private static final String[] VECTOR_NAMES = {
        "reset", "undefined_instruction", "software_interrupt", "prefetch_abort",
        "data_abort", "reserved", "irq", "fiq"
    };

    @Override
    protected void run() throws Exception {
        String imageName = getScriptArgs().length > 0 ? getScriptArgs()[0] : currentProgram.getName();
        long base = parseLongArg(1, currentProgram.getMinAddress().getOffset());
        long fileOffset = parseLongArg(2, 0);

        println("Annotating " + imageName + " base=0x" + Long.toHexString(base)
            + " fileOffset=0x" + Long.toHexString(fileOffset));

        annotateVectorTable(toAddr(base), imageName);
        annotateBabeface(toAddr(base + 0x20), imageName);
    }

    private long parseLongArg(int index, long fallback) {
        String[] args = getScriptArgs();
        if (args.length <= index) {
            return fallback;
        }
        return Long.decode(args[index]);
    }

    private void annotateVectorTable(Address vectorBase, String imageName) throws Exception {
        Listing listing = currentProgram.getListing();
        SymbolTable symbols = currentProgram.getSymbolTable();
        for (int i = 0; i < VECTOR_NAMES.length; i++) {
            Address vector = vectorBase.add(i * 4L);
            String label = imageName + "_vector_" + VECTOR_NAMES[i];
            symbols.createLabel(vector, label, SourceType.USER_DEFINED);
            if (listing.isUndefined(vector, vector.add(3))) {
                disassemble(vector);
            }
        }

        List<Address> targets = vectorTargets(vectorBase);
        for (int i = 0; i < targets.size(); i++) {
            Address target = targets.get(i);
            if (target == null || !currentProgram.getMemory().contains(target)) {
                continue;
            }
            String name = imageName + "_handler_" + VECTOR_NAMES[i];
            symbols.createLabel(target, name, SourceType.USER_DEFINED);
            addEntryPoint(target);
            disassemble(target);
        }
    }

    private List<Address> vectorTargets(Address vectorBase) throws Exception {
        List<Address> targets = new ArrayList<>();
        for (int i = 0; i < VECTOR_NAMES.length; i++) {
            Address vector = vectorBase.add(i * 4L);
            int opcode = getInt(vector);
            if ((opcode & 0xfffff000) != 0xe59ff000) {
                targets.add(null);
                continue;
            }
            int imm = opcode & 0xfff;
            Address pointerSlot = vector.add(8L + imm);
            if (!currentProgram.getMemory().contains(pointerSlot)) {
                targets.add(null);
                continue;
            }
            long rawTarget = Integer.toUnsignedLong(getInt(pointerSlot));
            boolean thumb = (rawTarget & 1L) != 0;
            Address target = toAddr(rawTarget & ~1L);
            targets.add(target);
            createBookmark(pointerSlot, "BCM2153",
                "Vector target for " + VECTOR_NAMES[i] + ": 0x"
                    + Long.toHexString(rawTarget) + (thumb ? " (Thumb)" : " (ARM)"));
        }
        return targets;
    }

    private void annotateBabeface(Address marker, String imageName) throws Exception {
        if (!currentProgram.getMemory().contains(marker) || getInt(marker) != 0xbabeface) {
            println("No BABEFACE marker at expected address " + marker);
            return;
        }
        currentProgram.getSymbolTable().createLabel(
            marker, imageName + "_babeface_header", SourceType.USER_DEFINED);

        Listing listing = currentProgram.getListing();
        for (int i = 0; i < 12; i++) {
            Address word = marker.add(i * 4L);
            if (!currentProgram.getMemory().contains(word)) {
                break;
            }
            if (listing.getDataAt(word) == null) {
                createDWord(word);
            }
        }

        createBookmark(marker, "BCM2153", "BABEFACE boot/image metadata marker");
    }
}
