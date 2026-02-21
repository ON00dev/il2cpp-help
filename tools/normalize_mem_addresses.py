import os
import re
import csv


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
    m2 = re.match(r"(.+?)\s+#([0-9A-Fa-fx]+)\s+(.+)", s)
    if m2:
        name = m2.group(1).strip()
        addr = m2.group(2).strip()
        vtype = m2.group(3).strip()
        return name, addr, vtype, ""
    return None


def normalize_addr(addr_str):
    s = addr_str.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    if not re.fullmatch(r"[0-9A-Fa-f]+", s):
        return None
    return "0x" + s.upper()


def ask_path(prompt, default_path):
    print(prompt)
    value = input("[" + default_path + "]: ").strip()
    if not value:
        return default_path
    return value


def main():
    default_in = "mem_addresses.txt"
    default_out_dir = "out"
    default_ghidra = os.path.join(default_out_dir, "ghidra_addresses.txt")
    default_csv = os.path.join(default_out_dir, "memory_addresses.csv")
    input_file = ask_path("Caminho do arquivo com endereços do GG", default_in)
    out_ghidra = ask_path("Caminho de saída para endereços do Ghidra", default_ghidra)
    out_csv = ask_path("Caminho de saída para CSV normalizado", default_csv)
    out_dir = os.path.dirname(out_ghidra) or "."
    if not os.path.isfile(input_file):
        print("Arquivo de entrada não encontrado:", input_file)
        return
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    rows = []
    addrs = []
    with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
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
        print("Nenhum endereço válido encontrado em", input_file)
        return
    with open(out_ghidra, "w", encoding="utf-8") as g:
        for a in addrs:
            g.write(a + "\n")
    with open(out_csv, "w", encoding="utf-8", newline="") as c:
        w = csv.DictWriter(c, fieldnames=["name", "address", "type", "module"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print("Gerado", out_ghidra, "com", len(addrs), "endereços")
    print("Gerado", out_csv, "com", len(rows), "linhas")


if __name__ == "__main__":
    main()
