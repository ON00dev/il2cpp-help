Pasta de trabalho para os dumps copiados do GameGuardian.

Estrutura esperada (após copiar do `/sdcard/Download/` do device):

- `GG_dumps_<package>/<tag>/...`
  - Gerado por `gg_dump_libs.lua`.
  - Contém subpastas como:
    - `libil2cpp.so_<base>/...`
    - `libmain.so_<base>/...`
  - É essa pasta `<package>/<tag>` que você seleciona no script:
    - `python il2cpp-help\tools\merge_gg_dumps.py`
  - O script:
    - Lista as sessões disponíveis dentro desta pasta.
    - Ignora automaticamente qualquer diretório `GG_dumps_results_*`.
    - Gera arquivos mesclados em `il2cpp-help/out/`:
      - `libil2cpp.so_merged.bin`
      - `libmain.so_merged.bin`
      - (opcionalmente `libunity.so_merged.bin`, se você incluir manualmente na lista).

- `GG_dumps_results_<package>/<tag>/...`
  - Gerado por `gg_dump_around_results.lua`.
  - São dumps localizados (janelas de memória) ao redor de endereços específicos.
  - Não são usados no merge das libs.
  - Podem ser indexados/relatados com:
    - `python il2cpp-help\tools\report_local_dumps.py`
  - Esse script gera um CSV (por padrão `il2cpp-help/out/local_dumps_report.csv`) com:
    - Caminho do `.bin`
    - Endereço inicial (`start`)
    - Endereço final (`end`)
    - Endereço central (`center`)
    - `package` e `tag` para referência futura no Ghidra.
