import os
import re
import csv

INPUT_FILE = "enderecos_memoria.txt"
OUT_DIR = "out"
OUT_GHIDRA = os.path.join(OUT_DIR, "ghidra_addresses.txt")
OUT_CSV = os.path.join(OUT_DIR, "memory_addresses.csv")


def parse_line(line):
    s = line.strip()
    if not s:
        return None
    if s.startswith("#"):
        return None
    if ";" in s:
        parts = [p.strip() for p in s.split(";")]
        if len(parts) < 2:
            return None
        name = parts[0] or ""
        addr = parts[1]
        vtype = parts[2] if len(parts) > 2 else ""
        module = parts[3] if len(parts) > 3 else ""
        return name, addr, vtype, module
    m = re.match(r"Var\s+#([0-9A-Fa-f]+)\s*\(([^)]+)\)\s*(.*)", s)
    if m:
        addr_hex = m.group(1)
        vtype = m.group(2).strip()
        name = m.group(3).strip()
        if not name:
            name = "Var_" + addr_hex.upper()
        return name, addr_hex, vtype, ""
    return None


def normalize_addr(addr_str):
    s = addr_str.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    if not re.fullmatch(r"[0-9A-Fa-f]+", s):
        return None
    return "0x" + s.upper()


def main():
    if not os.path.isfile(INPUT_FILE):
        print("Arquivo de entrada não encontrado:", INPUT_FILE)
        return
    os.makedirs(OUT_DIR, exist_ok=True)
    rows = []
    addrs = []
    with open(INPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_line(line)
            if not parsed:
                continue
            name, addr_raw, vtype, module = parsed
            addr_norm = normalize_addr(addr_raw)
            if not addr_norm:
                continue
            rows.append(
                {
                    "name": name,
                    "address": addr_norm,
                    "type": vtype,
                    "module": module,
                }
            )
            addrs.append(addr_norm)
    if not rows:
        print("Nenhum endereço válido encontrado em", INPUT_FILE)
        return
    with open(OUT_GHIDRA, "w", encoding="utf-8") as g:
        for a in addrs:
            g.write(a + "\n")
    with open(OUT_CSV, "w", encoding="utf-8", newline="") as c:
        w = csv.DictWriter(c, fieldnames=["name", "address", "type", "module"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print("Gerado", OUT_GHIDRA, "com", len(addrs), "endereços")
    print("Gerado", OUT_CSV, "com", len(rows), "linhas")


if __name__ == "__main__":
    main()

