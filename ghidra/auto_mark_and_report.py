from ghidra.program.model.symbol import SourceType

addr_input = askString("Endereços", "Informe endereços em hex, separados por espaço ou quebra de linha:")

if not addr_input:
    exit(0)

csv_file = askFile("Selecione arquivo CSV para salvar o relatório", "Salvar")
if csv_file is None:
    exit(0)

parts = addr_input.replace(",", " ").split()
rows = []

for p in parts:
    p = p.strip()
    if not p:
        continue
    orig = p
    if p.startswith("0x") or p.startswith("0X"):
        p = p[2:]
    try:
        va = int(p, 16)
    except:
        continue
    addr = toAddr(va)
    sym = getSymbolAt(addr)
    if sym:
        label_name = sym.getName()
    else:
        label_name = "Var_0x" + p.upper()
        try:
            createLabel(addr, label_name, True, SourceType.USER_DEFINED)
        except:
            pass
    refs = getReferencesTo(addr)
    if len(refs) == 0:
        rows.append((orig.upper(), label_name, "", ""))
    else:
        for ref in refs:
            ref_addr = ref.getFromAddress()
            func = getFunctionContaining(ref_addr)
            func_name = func.getName() if func else "NoFunc"
            rows.append((orig.upper(), label_name, "0x%X" % ref_addr.getOffset(), func_name))

with open(csv_file.getAbsolutePath(), "w") as f:
    f.write("var_address,var_label,ref_address,function_name\n")
    for r in rows:
        line = "%s,%s,%s,%s\n" % r
        f.write(line)

print("Relatório salvo em %s com %d linhas" % (csv_file.getAbsolutePath(), len(rows)))

