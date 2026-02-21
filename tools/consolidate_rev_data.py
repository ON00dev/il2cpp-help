import os
import csv
import json


def ask_path(prompt, default_path):
    print(prompt)
    value = input("[" + default_path + "]: ").strip()
    if not value:
        return default_path
    return value


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
    refs_by_var = {}
    funcs = {}
    if not os.path.isfile(path):
        return refs_by_var, funcs
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        r = csv.DictReader(f)
        for row in r:
            vaddr = row.get("var_address", "").strip()
            if not vaddr:
                continue
            vaddr = vaddr.upper()
            ref_addr = row.get("ref_address", "").strip()
            func = row.get("function_name", "").strip()
            if vaddr not in refs_by_var:
                refs_by_var[vaddr] = []
            refs_by_var[vaddr].append(
                {
                    "address": ref_addr,
                    "function": func,
                }
            )
            if func:
                if func not in funcs:
                    funcs[func] = {
                        "name": func,
                        "module": "",
                        "call_sites": set(),
                        "vars": set(),
                    }
                if ref_addr:
                    funcs[func]["call_sites"].add(ref_addr)
                funcs[func]["vars"].add(vaddr)
    return refs_by_var, funcs


def main():
    default_mem = os.path.join("out", "memory_addresses.csv")
    default_ghidra = os.path.join("out", "ghidra_refs.csv")
    default_out = os.path.join("out", "re_index.json")
    mem_csv = ask_path("Caminho do CSV de endereços normalizados", default_mem)
    ghidra_csv = ask_path("Caminho do CSV gerado pelo script do Ghidra", default_ghidra)
    out_json = ask_path("Caminho do JSON de saída", default_out)
    out_dir = os.path.dirname(out_json) or "."
    os.makedirs(out_dir, exist_ok=True)
    mem = load_memory_csv(mem_csv)
    refs_by_var, funcs = load_ghidra_csv(ghidra_csv)
    if not mem:
        print("Nenhuma entrada em", mem_csv)
        return
    variables = []
    for addr, meta in mem.items():
        entry = {
            "name": meta["name"],
            "address": meta["address"],
            "type": meta["type"],
            "module": meta["module"],
            "refs": refs_by_var.get(addr, []),
        }
        variables.append(entry)
    functions = []
    for fname, fmeta in funcs.items():
        vars_entries = []
        for vaddr in sorted(fmeta["vars"]):
            if vaddr in mem:
                meta = mem[vaddr]
                vars_entries.append(
                    {
                        "name": meta["name"],
                        "address": meta["address"],
                        "type": meta["type"],
                        "module": meta["module"],
                    }
                )
        modules = [v["module"] for v in vars_entries if v["module"]]
        module = modules[0] if modules else ""
        functions.append(
            {
                "name": fname,
                "module": module,
                "call_sites": sorted(fmeta["call_sites"]),
                "variables": vars_entries,
            }
        )
    data = {
        "variables": variables,
        "functions": functions,
    }
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print("Gerado", out_json, "com", len(variables), "variáveis e", len(functions), "funções")


if __name__ == "__main__":
    main()
