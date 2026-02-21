import json
import sys


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def index_re_data(re_data):
    by_name = {}
    if isinstance(re_data, dict):
        items = re_data.get("variables", [])
    else:
        items = re_data
    for entry in items:
        key = entry.get("name", "")
        if key:
            by_name[key] = entry
    return by_name


def gen_write_snippet(var_entry, feature):
    addr = var_entry["address"]
    vtype = feature.get("value_type", var_entry.get("type", "DWORD")).upper()
    val = feature["value"]
    if vtype.startswith("FLOAT"):
        write = "Memory.writeFloat(ptr(\"%s\"), %s)" % (addr, val)
    elif vtype.startswith("DOUBLE"):
        write = "Memory.writeDouble(ptr(\"%s\"), %s)" % (addr, val)
    else:
        write = "Memory.writeU32(ptr(\"%s\"), %s)" % (addr, val)
    return write


def gen_hook_snippet(var_entry, feature):
    func_name = feature.get("preferred_function", "")
    refs = var_entry.get("refs", [])
    target_ref = None
    if func_name:
        for r in refs:
            if r.get("function") == func_name:
                target_ref = r
                break
    if not target_ref and refs:
        target_ref = refs[0]
    if not target_ref:
        return "// nenhuma ref para %s\n" % var_entry["name"]
    addr = target_ref["address"]
    if not addr:
        return "// ref sem endereço para %s\n" % var_entry["name"]
    s = []
    s.append("Interceptor.attach(ptr(\"%s\"), {" % addr)
    s.append("  onEnter: function (args) {")
    if feature.get("patch") == "skip_damage":
        s.append("    return;")
    s.append("  }")
    s.append("});")
    return "\n".join(s)


def gen_frida(config, re_index_data):
    vars_by_name = index_re_data(re_index_data)
    lines = []
    lines.append("Java.perform(function() {")
    for feat in config.get("features", []):
        kind = feat.get("kind", "")
        target_var_name = feat.get("target_var", "")
        if not target_var_name or target_var_name not in vars_by_name:
            lines.append("// alvo não encontrado para feature " + feat.get("id", ""))
            continue
        var_entry = vars_by_name[target_var_name]
        if kind == "write_value":
            lines.append("// " + feat.get("label", feat.get("id", "")))
            lines.append(gen_write_snippet(var_entry, feat))
        elif kind == "hook_function":
            lines.append("// " + feat.get("label", feat.get("id", "")))
            lines.append(gen_hook_snippet(var_entry, feat))
    lines.append("});")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 3:
        print("uso: python generate_frida.py config.json out.js [re_index.json]")
        return
    cfg_path = sys.argv[1]
    out_js = sys.argv[2]
    if len(sys.argv) >= 4:
        re_index_path = sys.argv[3]
    else:
        default_re = "out/re_index.json"
        print("Caminho do re_index.json")
        value = input("[" + default_re + "]: ").strip()
        re_index_path = value or default_re
    config = load_json(cfg_path)
    re_index = load_json(re_index_path)
    code = gen_frida(config, re_index)
    with open(out_js, "w", encoding="utf-8") as f:
        f.write(code)
    print("Gerado", out_js)


if __name__ == "__main__":
    main()
