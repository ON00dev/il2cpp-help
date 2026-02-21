import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

public class import_segments_from_dir extends GhidraScript {

    private static class Segment {
        File file;
        long start;
        long end;

        Segment(File file, long start, long end) {
            this.file = file;
            this.start = start;
            this.end = end;
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("Nenhum Program ativo. Abra/crie um Program no CodeBrowser e rode o script a partir dele.");
            return;
        }
        File sessionDir = askDirectory("Selecione a pasta da sessão (GG_dumps_<package>/<tag>)", "Selecionar");
        if (sessionDir == null) {
            return;
        }
        String libName = askString("Nome da biblioteca", "libil2cpp.so");
        if (libName == null) {
            return;
        }
        libName = libName.trim();
        if (libName.isEmpty()) {
            println("Biblioteca não informada.");
            return;
        }
        List<Segment> segments = new ArrayList<>();
        walkSegments(sessionDir, libName, segments);
        if (segments.isEmpty()) {
            println("Nenhum segmento .bin encontrado para " + libName + " em " + sessionDir.getAbsolutePath());
            return;
        }
        Collections.sort(segments, Comparator.comparingLong(s -> s.start));
        Memory mem = currentProgram.getMemory();
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        TaskMonitor monitor = getMonitor();
        for (Segment seg : segments) {
            long start = seg.start;
            long end = seg.end;
            long length = end - start;
            if (length <= 0) {
                continue;
            }
            Address addr = space.getAddress(start);
            String blockName = String.format("seg_%016X", start);
            FileInputStream fis = new FileInputStream(seg.file);
            try {
                MemoryBlock block = mem.createInitializedBlock(blockName, addr, fis, length, monitor, false);
                block.setRead(true);
                block.setWrite(false);
                block.setExecute(false);
                println(String.format("Criado bloco %s em 0x%X (%d bytes) de %s", blockName, start, length,
                        seg.file.getAbsolutePath()));
            } finally {
                fis.close();
            }
        }
        println("Importação de segmentos concluída. Rode a análise manualmente se necessário.");
    }

    private void walkSegments(File root, String libName, List<Segment> out) {
        File[] children = root.listFiles();
        if (children == null) {
            return;
        }
        for (File f : children) {
            if (f.isDirectory()) {
                String base = f.getName();
                if (base.startsWith(libName + "_")) {
                    collectFromLibDir(f, out);
                }
                walkSegments(f, libName, out);
            }
        }
    }

    private void collectFromLibDir(File dir, List<Segment> out) {
        File[] files = dir.listFiles();
        if (files == null) {
            return;
        }
        for (File f : files) {
            if (!f.isFile()) {
                continue;
            }
            String name = f.getName();
            if (!name.endsWith(".bin")) {
                continue;
            }
            long[] range = parseRangeFromFilename(name);
            if (range == null) {
                continue;
            }
            out.add(new Segment(f, range[0], range[1]));
        }
    }

    private long[] parseRangeFromFilename(String name) {
        String[] parts = name.split("-");
        if (parts.length < 3) {
            return null;
        }
        try {
            String startHex = parts[parts.length - 2];
            String endPart = parts[parts.length - 1];
            int dot = endPart.indexOf('.');
            if (dot >= 0) {
                endPart = endPart.substring(0, dot);
            }
            long start = Long.parseUnsignedLong(startHex, 16);
            long end = Long.parseUnsignedLong(endPart, 16);
            if (end <= start) {
                return null;
            }
            return new long[] { start, end };
        } catch (Exception e) {
            return null;
        }
    }
}

