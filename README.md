# il2cpp-help

Toolkit para acelerar engenharia reversa de jogos/app IL2CPP usando:
- GameGuardian (dump em runtime)
- Ghidra (análise estática)
- Python (normalização e geração de scripts)

Tudo é pensado para ser reaproveitado em qualquer app, mudando apenas os dumps e os endereços que você descobriu.

---

## Como clonar e onde colocar esta pasta

Você pode usar este toolkit de duas maneiras:

1. **Dentro de um projeto maior** (por exemplo, um mod-menu específico de um jogo):
   - Clone o projeto principal (exemplo):
     ```bash
     git clone https://github.com/ON00dev/il2cpp-help.git
     cd il2cpp-help
     ```
   - Coloque a pasta `il2cpp-help/` dentro da raiz desse projeto (ou mantenha como submódulo).
2. **Como repositório separado apenas da ferramenta**:
   - Clone diretamente:
     ```bash
     git clone https://github.comON00dev/il2cpp-help.git
     cd il2cpp-help
     ```
   - Use `il2cpp-help/` como raiz de trabalho e mantenha os arquivos de jogo (`enderecos_memoria.txt`, dumps, etc.) em uma pasta ao lado ou num repo específico de jogo.

Nos exemplos abaixo, vou assumir que:

- Você está **dentro do repositório principal** que contém a pasta `il2cpp-help/`.
- O terminal já está posicionado na raiz desse repositório (por exemplo, após `cd il2cpp-help`).

---

## Estrutura de pastas

- `GG/`
  - `gg_dump_libs.lua` – dump de `libil2cpp.so`, `libunity.so`, `libmain.so`, etc.
  - `gg_dump_around_results.lua` – dump de memória ao redor de resultados do GG.
- `ghidra/`
  - `auto_mark_and_report.py` – script Jython que marca endereços e exporta refs para CSV.
- `tools/`
  - `normalize_mem_addresses.py` – normaliza `enderecos_memoria.txt` para uso no Ghidra.
  - `consolidate_rev_data.py` – junta CSV do GG + CSV do Ghidra em um `re_index.json` único.
  - `generate_frida.py` – gera script Frida a partir de um `config.json` + `re_index.json`.

Arquivos de trabalho esperados na raiz do projeto principal (fora de `il2cpp-help`):

- `enderecos_memoria.txt` – lista de endereços descobertos via GameGuardian.
- `GG/dumps/...` – dumps gerados pelo `gg_dump_libs.lua` (você copia do device para o PC).

---

## Passo a passo (visão geral)

1. No GameGuardian:
   - Rodar `gg_dump_libs.lua` para capturar libs importantes (il2cpp, unity, main).
   - Rodar `gg_dump_around_results.lua` se quiser dumps locais ao redor de valores encontrados.
2. No PC:
   - Organizar os dumps em `GG/dumps/` (dentro do repo principal).
   - Preencher/atualizar `enderecos_memoria.txt` com os endereços achados no GG.
   - Rodar `tools/normalize_mem_addresses.py` para gerar arquivos de apoio para o Ghidra.
3. No Ghidra:
   - Importar dumps mesclados das libs (você pode ter um script de merge separado).
   - Rodar `ghidra/auto_mark_and_report.py` passando os endereços normalizados.
   - Salvar o CSV de refs como `out/ghidra_refs.csv`.
4. No PC novamente:
   - Rodar `tools/consolidate_rev_data.py` para gerar `out/re_index.json`.
   - Criar um `config_<jogo>.json` com as features de mod.
   - Rodar `tools/generate_frida.py config_<jogo>.json <saida>.js` para gerar um script Frida de mod.

As seções abaixo detalham cada etapa.

---

## 1. GameGuardian – dumps de memória

### 1.1. Dump das libs principais

Script: `GG/gg_dump_libs.lua`

Fluxo:

1. Copiar `gg_dump_libs.lua` para a pasta de scripts do GameGuardian no device/emulador.
2. Abrir o jogo.
3. Abrir o GG, selecionar o processo do jogo.
4. Rodar `gg_dump_libs.lua`:
   - O script pede para você deixar o jogo na tela/ação crítica (ex.: pós login, lobby, batalha).
   - Depois mostra um menu com:
     - `Dumpar TODOS os módulos alvo`
     - Ou módulos específicos (`libil2cpp.so`, `libunity.so`, etc.).
5. Dumps são gravados em:
   - `/sdcard/Download/GG_dumps_<package>/...`
6. Copiar essa pasta inteira para o PC, em:
   - `GG/dumps/GG_dumps_<package>/`

### 1.2. Dump ao redor de resultados do GG

Script: `GG/gg_dump_around_results.lua`

Fluxo:

1. Com o jogo rodando, usar GG para:
   - Encontrar valores (moedas, vida, munição etc.).
   - Refine até ficar com uma lista pequena de endereços relevantes.
2. Deixar esses resultados selecionados (lista de Results do GG).
3. Rodar `gg_dump_around_results.lua`:
   - Ele pega até 500 resultados atuais.
   - Para cada um, dumpa uma janela de ±0x1000 bytes.
   - Os dumps e um `index.txt` são gravados em:
     - `/sdcard/Download/GG_dumps_results_<package>/`
4. Copiar essa pasta para o PC se quiser analisar com Ghidra/hexdump.

---

## 2. PC – normalizar endereços do GG

Arquivo de entrada esperado na raiz do repo principal:

- `enderecos_memoria.txt`

Formatos aceitos:

1. Formato “novo” (recomendado), separado por `;`:

```text
Nome;0xENDERECO;Tipo;Modulo
Moedas;0x7DB3D3F71CBC;DWORD;libil2cpp
Gemas;0x7DB3D3F71CC0;DWORD;libil2cpp
VidaEscudo;0x7DB3E1D5A98C;FLOAT;libil2cpp
Missil;0x7DB2E309A500;DWORD;libil2cpp
```

2. Formato “antigo” (compatível com anotações do GG):

```text
Var #7DB3D3F71CBC (DWORD) Moedas
Var #7DB3D3F71CC0 (DWORD) Gemas
Var #7DB3E1D5A98C (FLOAT) VidaEscudo
Var #7DB2E309A500 (DWORD/WORD) Missil
```

### 2.1. Normalizar endereços para o Ghidra

Script: `il2cpp-help/tools/normalize_mem_addresses.py`

Uso (a partir da raiz do projeto principal):

```bash
python il2cpp-help\tools\normalize_mem_addresses.py
```

Ele gera:

- `out/ghidra_addresses.txt` – lista de endereços em formato `0x...`, um por linha.
- `out/memory_addresses.csv` – CSV com colunas `name,address,type,module`.

Esse arquivo `ghidra_addresses.txt` é o que você cola dentro do Ghidra.

---

## 3. Ghidra – marcar endereços e exportar referências

Script: `il2cpp-help/ghidra/auto_mark_and_report.py`

### 3.1. Preparar o programa no Ghidra

1. Mesclar as páginas da lib (il2cpp/unity/main) em um único binário ou importar cada dump por página com o endereço correto.
2. Importar no Ghidra como `Raw Binary`:
   - Language: `AARCH64:LE:64:v8A:default` (para ARM64).
   - Image Base / Load Address: usar o endereço base real (o mesmo da sessão do dump).

### 3.2. Rodar o script no Ghidra

1. Copiar `il2cpp-help/ghidra/auto_mark_and_report.py` para a pasta de scripts do Ghidra, ou adicionar a pasta via Script Manager.
2. Abrir o programa (por exemplo `libil2cpp_merged.bin`) no Ghidra.
3. Abrir o Script Manager e executar `auto_mark_and_report.py`.
4. Quando o script pedir “Endereços”:
   - Abrir `out/ghidra_addresses.txt` no editor e copiar todo o conteúdo.
   - Colar no diálogo do Ghidra (um ou vários endereços, tanto faz).
5. O script vai pedir um arquivo CSV para salvar o relatório:
   - Escolher `out/ghidra_refs.csv` (ou salvar com esse nome).

Saída do script:

- Cria (se não existir) labels para cada endereço (ex.: `Var_0x...`).
- Encontra todas as referências a esses endereços.
- Gera um CSV com colunas:
  - `var_address,var_label,ref_address,function_name`

Esse CSV é usado na próxima etapa.

---

## 4. PC – consolidar dados em `re_index.json`

Script: `il2cpp-help/tools/consolidate_rev_data.py`

Pré-requisitos:

- `out/memory_addresses.csv` (do passo 2).
- `out/ghidra_refs.csv` (do passo 3).

Uso:

```bash
python il2cpp-help\tools\consolidate_rev_data.py
```

Saída:

- `out/re_index.json`

Estrutura simplificada de cada entrada no JSON:

```json
{
  "name": "Moedas",
  "address": "0x7DB3D3F71CBC",
  "type": "DWORD",
  "module": "libil2cpp",
  "refs": [
    {
      "address": "0x7CAE19212345",
      "function": "Player_AddCoins"
    }
  ]
}
```

Esse arquivo é a base para geração de scripts de mod (Frida, etc.).

---

## 5. Geração de script Frida

Script: `il2cpp-help/tools/generate_frida.py`

Você define um JSON de configuração por jogo, por exemplo:

`config_aircombat.json`:

```json
{
  "game": {
    "name": "Air Combat Online",
    "package": "com.vector.apexcombat.google"
  },
  "features": [
    {
      "id": "infinite_coins",
      "label": "Moedas infinitas",
      "kind": "write_value",
      "target_var": "Moedas",
      "value": 999999999
    },
    {
      "id": "godmode",
      "label": "Godmode Vida/Escudo",
      "kind": "hook_function",
      "target_var": "VidaEscudo",
      "preferred_function": "Health_ApplyDamage",
      "patch": "skip_damage"
    }
  ]
}
```

Campos importantes:

- `target_var` deve bater com `name` em `re_index.json`.
- `kind` pode ser:
  - `write_value` – escreve um valor direto na memória.
  - `hook_function` – gera um hook básico na função associada.

### 5.1. Gerar script Frida

Uso:

```bash
python il2cpp-help\tools\generate_frida.py config_aircombat.json aircombat_mod.js
```

Pré-requisito:

- `out/re_index.json` gerado no passo 4.

Saída:

- `aircombat_mod.js` – script Frida que:
  - Dentro de `Java.perform(...)` aplica writes (`Memory.write...`) para features `write_value`.
  - Cria `Interceptor.attach(...)` nas funções associadas para `hook_function`.

Esse script pode ser carregado via Frida:

```bash
frida -U -n <processo> -l aircombat_mod.js
```

---

## 6. Fluxo final resumido

1. GG:
   - Encontrar valores importantes (vida, moedas, armas...).
   - Dump de libs com `gg_dump_libs.lua`.
   - Opcional: dump local com `gg_dump_around_results.lua`.
2. PC:
   - Copiar dumps para `GG/dumps/...`.
   - Registrar endereços em `enderecos_memoria.txt`.
   - Rodar `il2cpp-help/tools/normalize_mem_addresses.py`.
3. Ghidra:
   - Importar dumps (il2cpp/unity/main).
   - Rodar `il2cpp-help/ghidra/auto_mark_and_report.py` com `out/ghidra_addresses.txt`.
   - Salvar CSV em `out/ghidra_refs.csv`.
4. PC:
   - Rodar `il2cpp-help/tools/consolidate_rev_data.py` → `out/re_index.json`.
   - Criar `config_<jogo>.json` com as features.
   - Rodar `il2cpp-help/tools/generate_frida.py` → script Frida pronto para uso.

Com isso, grande parte do trabalho pesado de engenharia reversa fica padronizado e reaproveitável entre jogos diferentes.
