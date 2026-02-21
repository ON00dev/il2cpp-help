import os
import csv


def ask_path(prompt, default_path):
    print(prompt)
    value = input("[" + default_path + "]: ").strip()
    if not value:
        return default_path
    return value


def collect_local_dumps(root_dir):
    entries = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        if "GG_dumps_results_" not in dirpath:
            continue
        for name in filenames:
            if not name.endswith(".bin"):
                continue
            full = os.path.join(dirpath, name)
            parts = name.split("-")
            if len(parts) < 3:
                continue
            try:
                start_hex = parts[-2]
                end_hex = parts[-1].split(".")[0]
                start = int(start_hex, 16)
                end = int(end_hex, 16)
            except ValueError:
                continue
            size = os.path.getsize(full)
            center = start + (end - start) // 2
            radius = (end - start) // 2
            rel = os.path.relpath(full, ".")
            path_parts = dirpath.split(os.sep)
            pkg = ""
            tag = ""
            for i, p in enumerate(path_parts):
                if p.startswith("GG_dumps_results_"):
                    pkg = p[len("GG_dumps_results_") :]
                    if i + 1 < len(path_parts):
                        tag = path_parts[i + 1]
                    break
            entries.append(
                {
                    "package": pkg,
                    "tag": tag,
                    "file": rel,
                    "start": "0x%X" % start,
                    "end": "0x%X" % end,
                    "center": "0x%X" % center,
                    "radius": "0x%X" % radius,
                    "size_bytes": str(size),
                }
            )
    return entries


def main():
    default_root = os.path.join("GG", "dumps")
    root_dir = ask_path(
        "Pasta raiz onde estão os dumps de resultados do GG (GG_dumps_results_*)",
        default_root,
    )
    default_out = os.path.join("out", "local_dumps_report.csv")
    out_path = ask_path("Caminho do CSV de saída para o relatório", default_out)
    out_dir = os.path.dirname(out_path) or "."
    os.makedirs(out_dir, exist_ok=True)
    entries = collect_local_dumps(root_dir)
    if not entries:
        print("Nenhum dump localizado encontrado em", root_dir)
        return
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        fieldnames = [
            "package",
            "tag",
            "file",
            "start",
            "end",
            "center",
            "radius",
            "size_bytes",
        ]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for e in entries:
            w.writerow(e)
    print("Relatório gerado em", out_path, "com", len(entries), "entradas")
    print(
        "Use a coluna 'file' como caminho do bin e 'start' como base ao importar como Raw Binary no Ghidra."
    )


if __name__ == "__main__":
    main()

