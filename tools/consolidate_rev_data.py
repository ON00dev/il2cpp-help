import os
import csv
import json

MEM_CSV = os.path.join("out", "memory_addresses.csv")
GHIDRA_CSV = os.path.join("out", "ghidra_refs.csv")
OUT_JSON = os.path.join("out", "re_index.json")


def load_memory_csv(path):
    out = {}
    if not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        r = csv.DictReader(f)
        for row in r:
            addr = row.get("address", "").strip()
            if not addr:
                continue
            out[addr.upper()] = {
                "name": row.get("name", "").strip(),
                "address": addr.upper(),
                "type": row.get("type", "").strip(),
                "module": row.get("module", "").strip(),
            }
    return out


def load_ghidra_csv(path):
    out = {}
    if not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        r = csv.DictReader(f)
        for row in r:
            vaddr = row.get("var_address", "").strip()
            if not vaddr:
                continue
            vaddr = vaddr.upper()
            ref_addr = row.get("ref_address", "").strip()
            func = row.get("function_name", "").strip()
            if vaddr not in out:
                out[vaddr] = []
            out[vaddr].append(
                {
                    "address": ref_addr,
                    "function": func,
                }
            )
    return out


def main():
    os.makedirs("out", exist_ok=True)
    mem = load_memory_csv(MEM_CSV)
    refs = load_ghidra_csv(GHIDRA_CSV)
    if not mem:
        print("Nenhuma entrada em", MEM_CSV)
        return
    data = []
    for addr, meta in mem.items():
        entry = {
            "name": meta["name"],
            "address": meta["address"],
            "type": meta["type"],
            "module": meta["module"],
            "refs": refs.get(addr, []),
        }
        data.append(entry)
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print("Gerado", OUT_JSON, "com", len(data), "entradas")


if __name__ == "__main__":
    main()

