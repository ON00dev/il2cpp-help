// Ghidra script: auto_mark_and_report.java
// Lê endereços em hex informados pelo usuário, cria/usa labels
// e exporta referências para um CSV.

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;

public class auto_mark_and_report extends GhidraScript {

    @Override
    public void run() throws Exception {
        String addrInput = askString("Endereços", "Informe endereços em hex, separados por espaço ou quebra de linha:");
        if (addrInput == null || addrInput.trim().isEmpty()) {
            println("Nenhum endereço informado.");
            return;
        }

        java.io.File csvFile = askFile("Selecione arquivo CSV para salvar o relatório", "Salvar");
        if (csvFile == null) {
            println("Operação cancelada.");
            return;
        }

        String[] parts = addrInput.replace(",", " ").split("\\s+");
        List<String[]> rows = new ArrayList<>();

        for (String p : parts) {
            if (p == null) {
                continue;
            }
            p = p.trim();
            if (p.isEmpty()) {
                continue;
            }
            String orig = p;
            if (p.startsWith("0x") || p.startsWith("0X")) {
                p = p.substring(2);
            }
            long va;
            try {
                va = Long.parseLong(p, 16);
            } catch (Exception e) {
                println("Ignorando entrada inválida: " + orig);
                continue;
            }
            Address addr = toAddr(va);
            if (addr == null) {
                println("Endereço inválido no programa: " + orig);
                continue;
            }

            Symbol sym = getSymbolAt(addr);
            String labelName;
            if (sym != null) {
                labelName = sym.getName();
            } else {
                labelName = "Var_0x" + p.toUpperCase();
                try {
                    createLabel(addr, labelName, true, SourceType.USER_DEFINED);
                } catch (Exception e) {
                    println("Falha ao criar label em " + orig + ": " + e.getMessage());
                }
            }

            Reference[] refArr = getReferencesTo(addr);
            if (refArr.length == 0) {
                rows.add(new String[] { orig.toUpperCase(), labelName, "", "" });
            } else {
                for (Reference ref : refArr) {
                    Address fromAddr = ref.getFromAddress();
                    Function func = getFunctionContaining(fromAddr);
                    String funcName = (func != null) ? func.getName() : "NoFunc";
                    String refAddrStr = "0x" + Long.toHexString(fromAddr.getOffset()).toUpperCase();
                    rows.add(new String[] { orig.toUpperCase(), labelName, refAddrStr, funcName });
                }
            }
        }

        writeCsv(csvFile, rows);
        println("Relatório salvo em " + csvFile.getAbsolutePath() + " com " + rows.size() + " linhas");
    }

    private void writeCsv(java.io.File csvFile, List<String[]> rows) throws IOException {
        FileWriter fw = new FileWriter(csvFile);
        fw.write("var_address,var_label,ref_address,function_name\n");
        for (String[] r : rows) {
            String line = String.join(",", escapeCsv(r[0]), escapeCsv(r[1]), escapeCsv(r[2]), escapeCsv(r[3]));
            fw.write(line);
            fw.write("\n");
        }
        fw.close();
    }

    private String escapeCsv(String v) {
        if (v == null) {
            return "";
        }
        if (v.contains(",") || v.contains("\"") || v.contains("\n") || v.contains("\r")) {
            String escaped = v.replace("\"", "\"\"");
            return "\"" + escaped + "\"";
        }
        return v;
    }
}
