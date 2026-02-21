import os


def ask_path(prompt, default_path):
    print(prompt)
    value = input("[" + default_path + "]: ").strip()
    if not value:
        return default_path
    return value


def collect_segments(root_dir, lib_filter):
    segments = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        base = os.path.basename(dirpath)
        if not base.startswith(lib_filter + "_"):
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
            if size != (end - start):
                print("Aviso: tamanho do arquivo não bate com range:", full)
            segments.append(
                {
                    "path": full,
                    "start": start,
                    "end": end,
                }
            )
    return segments


def merge_segments(segments, out_path):
    if not segments:
        print("Nenhum segmento encontrado.")
        return
    segments.sort(key=lambda s: s["start"])
    base = segments[0]["start"]
    last_end = max(s["end"] for s in segments)
    total = last_end - base
    if total > 5 * 1024 * 1024 * 1024:
        print(
            "Intervalo virtual muito grande (%.2f GB). Provavelmente há gaps enormes entre segmentos."
            % (total / (1024 * 1024 * 1024))
        )
        print("Ignorando merge para evitar arquivo gigante:", out_path)
        return
    print("Base mínima: 0x%X" % base)
    print("Endereço final: 0x%X" % last_end)
    print("Tamanho total aproximado: %d bytes" % total)
    with open(out_path, "wb") as out:
        out.truncate(total)
        for seg in segments:
            rel_off = seg["start"] - base
            print("Escrevendo %s em offset 0x%X" % (seg["path"], rel_off))
            with open(seg["path"], "rb") as f:
                out.seek(rel_off)
                out.write(f.read())
    print("Arquivo mesclado gerado em:", out_path)
    print("Use base 0x%X ao importar como Raw Binary no Ghidra." % base)


def find_sessions(base_root):
    sessions = []
    if not os.path.isdir(base_root):
        return sessions
    for pkg_dir in os.listdir(base_root):
        if not pkg_dir.startswith("GG_dumps_"):
            continue
        if pkg_dir.startswith("GG_dumps_results_"):
            continue
        pkg_path = os.path.join(base_root, pkg_dir)
        if not os.path.isdir(pkg_path):
            continue
        subdirs = [
            d
            for d in os.listdir(pkg_path)
            if os.path.isdir(os.path.join(pkg_path, d))
        ]
        if subdirs:
            for tag in subdirs:
                session_path = os.path.join(pkg_path, tag)
                label = pkg_dir + "/" + tag
                sessions.append((label, session_path))
        else:
            sessions.append((pkg_dir, pkg_path))
    return sessions


def main():
    default_root = os.path.join("GG", "dumps")
    root_dir = ask_path(
        "Pasta raiz onde estão os dumps do GG (contendo pastas lib*.so_...)", default_root
    )
    sessions = find_sessions(root_dir)
    if sessions:
        print("Selecione qual sessão de dump deseja mesclar:")
        for idx, (label, path) in enumerate(sessions, start=1):
            print("%d) %s -> %s" % (idx, label, path))
        sel = input("[1]: ").strip()
        if not sel:
            sel_idx = 1
        else:
            try:
                sel_idx = int(sel)
            except ValueError:
                sel_idx = 1
        if 1 <= sel_idx <= len(sessions):
            root_dir = sessions[sel_idx - 1][1]
            print("Usando sessão:", sessions[sel_idx - 1][0])
    default_libs = "libil2cpp.so,libmain.so"
    print("Lista de bibliotecas para mesclar, separadas por vírgula.")
    libs_str = input("[" + default_libs + "]: ").strip()
    if not libs_str:
        libs_str = default_libs
    libs = [x.strip() for x in libs_str.split(",") if x.strip()]
    if not libs:
        print("Nenhuma biblioteca informada.")
        return
    base_dir = os.path.dirname(os.path.dirname(__file__))
    out_dir = os.path.join(base_dir, "out")
    os.makedirs(out_dir, exist_ok=True)
    for lib_name in libs:
        lib_filter = lib_name
        out_path = os.path.join(out_dir, lib_name + "_merged.bin")
        print("\n--- Mesclando segmentos para", lib_name, "---")
        segments = collect_segments(root_dir, lib_filter)
        print("Encontrados", len(segments), "segmentos para", lib_name)
        merge_segments(segments, out_path)


if __name__ == "__main__":
    main()

