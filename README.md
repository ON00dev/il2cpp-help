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
     git clone https://github.com/ON00dev/il2cpp-help.git
     cd il2cpp-help
     ```
   - Use `il2cpp-help/` como raiz de trabalho e mantenha os arquivos de jogo (`mem_addresses.txt`, dumps, etc.) em uma pasta ao lado ou num repo específico de jogo.

Nos exemplos abaixo, vou assumir que:

- Você está **dentro do repositório principal** que contém a pasta `il2cpp-help/`.
- O terminal já está posicionado na raiz desse repositório (por exemplo, após `cd il2cpp-help`).

---

## Estrutura de pastas

- `GG/`
  - `gg_dump_libs.lua` – dump de `libil2cpp.so`, `libunity.so`, `libmain.so`, etc.
  - `gg_dump_around_results.lua` – dump de memória ao redor de resultados do GG.
- `ghidra/`
  - `auto_mark_and_report.py` – script Python (Jython) que marca endereços e exporta refs para CSV.
  - `auto_mark_and_report.java` – versão equivalente em Java, para usar sem Python/PyGhidra.
- `tools/`
  - `normalize_mem_addresses.py` – normaliza `mem_addresses.txt` para uso no Ghidra.
  - `generate_frida.py` – gera script Frida a partir de um `config.json` + `re_index.json`.
  - `merge_gg_dumps.py` – mescla páginas de dump das libs em arquivos `_merged.bin` dentro de `il2cpp-help/out`.
  - `report_local_dumps.py` – gera relatório CSV dos dumps localizados de resultados (`GG_dumps_results_*`).

Arquivos de trabalho esperados na raiz do projeto principal (fora de `il2cpp-help`):

- `mem_addresses.txt` – lista de endereços descobertos via GameGuardian.

---

## Passo a passo (visão geral)

1. No GameGuardian:
   - Rodar `gg_dump_libs.lua` para capturar libs importantes (il2cpp, unity, main) para uma sessão/tela específica (ex.: lobby, batalha).
   - Rodar `gg_dump_around_results.lua` se quiser dumps locais ao redor de valores encontrados.
   - Opcional: usar `gg_find_energy_shield.lua` para ajudar a filtrar candidatos de Energia/Blindagem.
2. No PC:
   - Organizar os dumps em `GG/dumps/` (dentro do repo principal), preservando a estrutura `GG_dumps_<package>/<tag>/`.
   - Rodar `tools/merge_gg_dumps.py` para gerar `libil2cpp.so_merged.bin` e `libmain.so_merged.bin` em `il2cpp-help/out`.
   - Preencher/atualizar `enderecos_memoria.txt` com os endereços achados no GG.
   - Rodar `tools/normalize_mem_addresses.py` para gerar arquivos de apoio para o Ghidra.
3. No Ghidra:
   - Importar dumps mesclados das libs a partir de `il2cpp-help/out`.
   - Rodar `ghidra/auto_mark_and_report.py` passando os endereços normalizados.
   - Salvar o CSV de refs como `il2cpp-help/out/ghidra_refs.csv`.
4. No PC novamente:
   - Rodar `tools/consolidate_rev_data.py` para gerar `il2cpp-help/out/re_index.json`.
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
   - `/sdcard/Download/GG_dumps_<package>/<tag>/...`
   - Dentro dessa pasta, cada lib terá subpastas do tipo `libil2cpp.so_<base>`, `libmain.so_<base>`, etc.
6. Copiar essa pasta inteira para o PC, em:
   - `GG/dumps/GG_dumps_<package>/<tag>/`

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
     - `/sdcard/Download/GG_dumps_results_<package>/<tag>/`
4. Copiar essa pasta para o PC se quiser analisar com Ghidra/hexdump, em:
   - `GG/dumps/GG_dumps_results_<package>/<tag>/`
5. Esses dumps de resultados não são usados no merge das libs, mas podem ser relatados depois com `tools/report_local_dumps.py`.
   
### 1.3. Ajuda para encontrar Energia e Blindagem
   
Script: `GG/gg_find_energy_shield.lua`
   
Fluxo:
   
1. Copiar `gg_find_energy_shield.lua` para a pasta de scripts do GG.
2. Abrir o jogo, selecionar o processo no GG e rodar o script.
3. Escolher o tipo de valor inicial (`DWORD` ou `FLOAT`).
4. Usar o menu em etapas:
   - Energia:
     - Etapa 1: buscar 100 antes de gastar.
     - Etapa 2: após gastar (valor cai).
     - Etapa 3: após regenerar (valor volta para 100).
   - Blindagem:
     - Etapa 1: buscar 100 com blindagem cheia.
     - Etapa 2: após levar dano (cai de 100).
     - Etapa 3: após regenerar só a Energia (blindagem continua baixa).
5. Cada etapa é chamada manualmente abrindo o GG; o script fica em loop esperando você abrir o GG de novo, sem depender de caixas de diálogo que travam quando troca de app.
6. No final de cada fluxo (Energia/Blindagem), ele carrega os candidatos na lista de resultados do GG para você testar/congelar/refinar.
   
Esse script não participa direto do pipeline com Ghidra, mas ajuda a encontrar endereços candidatos de Energia/Blindagem para depois registrar em `enderecos_memoria.txt`.
   
---
   
## 2. PC – normalizar endereços do GG

Arquivo de entrada esperado na raiz do repo principal:

- `enderecos_memoria.txt`

Formatos aceitos:

1. Formato “novo” (recomendado), separado por `;` (sem módulo obrigatório):

```text
Nome;0xENDERECO;Tipo;Modulo
Moedas;0x7DB3D3F71CBC;DWORD;libil2cpp
Gemas;0x7DB3D3F71CC0;DWORD;libil2cpp
VidaEscudo;0x7DB3E1D5A98C;FLOAT;libil2cpp
Missil;0x7DB2E309A500;DWORD;libil2cpp
```

2. Formato “livre” anotado à mão, sem módulo, usando `Nome #ENDERECO Tipo`:

```text
Moedas #7DB3D3F71CBC DWORD
Gemas #7DB3D3F71CC0 DWORD
VidaEscudo #7DB3E1D5A98C FLOAT
Missil #7DB2E309A500 DWORD/WORD
```


### 2.1. Normalizar endereços para o Ghidra

Script: `il2cpp-help/tools/normalize_mem_addresses.py`

Uso (a partir da raiz do projeto principal, o script vai perguntar pelos caminhos e sugerir padrões):

```bash
python il2cpp-help\tools\normalize_mem_addresses.py
```

Ele gera:

Ele vai perguntar:

- Caminho do arquivo com endereços do GG (default: `enderecos_memoria.txt`).
- Caminho de saída para endereços do Ghidra (default: `il2cpp-help/out/ghidra_addresses.txt`).
- Caminho de saída para CSV normalizado (default: `il2cpp-help/out/memory_addresses.csv`).

Ele gera:

- `il2cpp-help/out/ghidra_addresses.txt` – lista de endereços em formato `0x...`, um por linha.
- `il2cpp-help/out/memory_addresses.csv` – CSV com colunas `name,address,type,module`.

Esse arquivo `ghidra_addresses.txt` é o que você cola dentro do Ghidra.

---

## 3. Ghidra – marcar endereços e exportar referências

Script: `il2cpp-help/ghidra/auto_mark_and_report.py`

### 3.1. Preparar o programa no Ghidra

1. Mesclar as páginas das libs (il2cpp/main) em um único binário usando:
   - `python il2cpp-help\tools\merge_gg_dumps.py`
   - O script:
     - Lista as sessões disponíveis dentro de `GG/dumps/GG_dumps_<package>/<tag>/`.
     - Ignora automaticamente pastas `GG_dumps_results_*` (que são dumps localizados de resultados do GG).
     - Gera arquivos como `il2cpp-help/out/libil2cpp.so_merged.bin` e `il2cpp-help/out/libmain.so_merged.bin`.
   - Por padrão, `libunity.so` não é mesclado para evitar arquivos gigantes; inclua manualmente na lista de libs somente se realmente precisar.
2. Importar os `_merged.bin` no Ghidra como `Raw Binary`:
   - Language: `AARCH64:LE:64:v8A:default` (para ARM64).
   - Image Base / Load Address: usar o endereço base real (o mesmo da sessão do dump, mostrado pelo script de merge).

### 3.2. Rodar o script no Ghidra

Você tem duas opções, dependendo do suporte a Python no seu Ghidra:

### Opção A – Usar a versão Java (recomendado se aparecer erro de Python)

Esta opção não depende de PyGhidra nem de nenhuma integração extra de Python.

1. Copiar `il2cpp-help/ghidra/auto_mark_and_report.java` para a pasta de scripts do Ghidra ou adicionar a pasta via Script Manager.
2. No Script Manager, filtrar por linguagem `Java` e localizar `auto_mark_and_report`.
3. Executar o script normalmente e seguir o mesmo fluxo descrito abaixo (os diálogos são os mesmos).

### Opção B – Usar a versão Python/Jython

Se o seu Ghidra estiver configurado com suporte a Python (PyGhidra ou similar) e **não** aparecer a mensagem “Python is not available”, você pode usar a versão `.py`:

1. Copiar `il2cpp-help/ghidra/auto_mark_and_report.py` para a pasta de scripts do Ghidra, ou adicionar a pasta via Script Manager.
2. Abrir o programa (por exemplo `libil2cpp_merged.bin`) no Ghidra.
3. Abrir o Script Manager e executar `auto_mark_and_report.py`.
4. Quando o script pedir “Endereços”:
   - Abrir `il2cpp-help/out/ghidra_addresses.txt` no editor e copiar todo o conteúdo.
   - Colar no diálogo do Ghidra (um ou vários endereços, tanto faz).
5. O script vai pedir um arquivo CSV para salvar o relatório:
   - Escolher `il2cpp-help/out/ghidra_refs.csv` (ou salvar com esse nome).

Saída do script:

- Cria (se não existir) labels para cada endereço (ex.: `Var_0x...`).
- Encontra todas as referências a esses endereços.
- Gera um CSV com colunas:
  - `var_address,var_label,ref_address,function_name`

Esse CSV é usado na próxima etapa.

---

## 4. PC – consolidar dados em `re_index.json`

Script: `il2cpp-help/tools/consolidate_rev_data.py` (o script pergunta pelos caminhos dos arquivos)

Pré-requisitos:

- CSV com endereços normalizados (por padrão `il2cpp-help/out/memory_addresses.csv`).
- CSV com refs do Ghidra (por padrão `il2cpp-help/out/ghidra_refs.csv`).

Uso:

```bash
python il2cpp-help\tools\consolidate_rev_data.py
```

Saída principal (por padrão `il2cpp-help/out/re_index.json`), com duas visões:

- `variables`: lista de variáveis que você marcou no GG:
  - `name`, `address`, `type`, `module`
  - `refs`: lista de refs cruas com `address` (call site) e `function` (nome da função no Ghidra).
- `functions`: lista de funções que tocam nessas variáveis:
  - `name`: nome da função (ex.: `Health_ApplyDamage`).
  - `module`: módulo associado (ex.: `libil2cpp`).
  - `call_sites`: lista de endereços onde a função aparece como referência.
  - `variables`: lista de variáveis associadas àquela função, cada uma com `name/address/type/module`.

Essa visão orientada a funções é a que você usa para localizar e alterar métodos no smali/mod menu.

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
python il2cpp-help\tools\generate_frida.py config_aircombat.json aircombat_mod.js [caminho_do_re_index.json]
```

Pré-requisito:

- `re_index.json` gerado no passo 4 (por padrão `il2cpp-help/out/re_index.json`).

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
   - Importar dumps mesclados (il2cpp/main) a partir de `il2cpp-help/out`.
   - Rodar `il2cpp-help/ghidra/auto_mark_and_report.py` com `il2cpp-help/out/ghidra_addresses.txt`.
   - Salvar CSV em `il2cpp-help/out/ghidra_refs.csv`.
4. PC:
   - Rodar `il2cpp-help/tools/consolidate_rev_data.py` → `il2cpp-help/out/re_index.json`.
   - Criar `config_<jogo>.json` com as features.
   - Rodar `il2cpp-help/tools/generate_frida.py` → script Frida pronto para uso.

Com isso, grande parte do trabalho pesado de engenharia reversa fica padronizado e reaproveitável entre jogos diferentes.
