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
        annotateKnownImageDetails(imageName, base);
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
            if (!imageName.startsWith("bcmboot")) {
                addEntryPoint(target);
            }
            disassemble(target);
        }
    }

    private void annotateKnownImageDetails(String imageName, long base) throws Exception {
        if (imageName.startsWith("bcmboot")) {
            labelAndBookmark(base + 0x30, "bcmboot_entry_like_start",
                "Entry-like setup path; sets SP before early calls");
            labelAndBookmark(base + 0x3ac, "bcmboot_copy_0x40_bytes_helper",
                "Copies 0x40 bytes through 0x0c0ca000/0x0c0ca008 MMIO path");
            labelAndBookmark(base + 0x40c, "bcmboot_nand_width_test",
                "Checks 0x08880008 bit 0x02000000; controls 8-bit vs 16-bit data reads");
            labelAndBookmark(base + 0x598, "bcmboot_debug_putc_delay",
                "Byte output helper using 0x08821000 plus delay");
            labelAndBookmark(base + 0x5e8, "bcmboot_debug_getc_poll",
                "Byte input poll helper using 0x08820000");
            labelAndBookmark(base + 0x83c, "bcmboot_flash_controller_init",
                "Initializes controller register block at 0x0c0c9000");
            labelAndBookmark(base + 0x8b8, "bcmboot_flash_controller_command",
                "Issues controller command/address sequence through 0x0c0c9000");
            labelAndBookmark(base + 0x960, "bcmboot_flash_controller_read_status",
                "Reads controller status/data through 0x0c0c9000");
            labelAndBookmark(base + 0x9c4, "bcmboot_flash_probe_or_fixup",
                "Uses table at 0x28007800 and flash controller helpers");
            labelAndBookmark(0x08400000L, "boot2_runtime_base_candidate",
                "Next-stage RAM image base checked and jumped to by bcmboot");
            labelAndBookmark(0x08700800L, "bcmboot_initial_stack_top",
                "Stack top computed by bcmboot entry-like setup");
        }
    }

    private void labelAndBookmark(long rawAddress, String label, String note) throws Exception {
        Address address = toAddr(rawAddress);
        if (!currentProgram.getMemory().contains(address)) {
            return;
        }
        currentProgram.getSymbolTable().createLabel(address, label, SourceType.USER_DEFINED);
        createBookmark(address, "BCM2153", note);
        disassemble(address);
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
