# 1. libil2cpp.so

## O que é

É o “resultado” do IL2CPP: o C# do jogo (scripts, lógica de gameplay, UI lógica, etc.) compilado para C++ e depois para máquina.

## O que costuma ter lá

- Funções que vieram de métodos C# (`Player.TakeDamage`, `AddGold`, `UpdateEnergyBar`, etc).
- Estruturas e campos de classes (`Player`, `Weapon`, `MatchManager`…).
- Lógica de recursos: moedas, gemas, energia, blindagem, dano, cooldown, etc.

## Por que é importante pra você

### É normalmente o alvo principal para

- Achar funções que mexem em vida/energia/blindagem.
- Criar hooks (Frida/Smali) em funções de lógica de jogo.
- Fazer patches estáticos de comportamento (godmode, ammo infinita, etc.).

### É o melhor lugar pra casar

- endereços que você capturou via GG → offsets relativos de `libil2cpp.so` → funções no Ghidra.

**Resumo:** se você quer mexer em “regra do jogo” (quanto dano leva, quanto ganha de moeda, quando recarrega energia), `libil2cpp.so` é o número 1.

---

# 2. libmain.so

## O que é

- Biblioteca nativa específica do jogo/app.
- Ponto de entrada da aplicação (`android_main`/JNI), inicialização, integração com SDKs, às vezes pedaços de gameplay críticos escritos em C++ direto.

## O que costuma ter lá

- Código que “cola” Unity/IL2CPP com o resto do app.
- Chamadas para libs de terceiros (analytics, ads, anticheat, rede).
- Em alguns jogos, funções de lógica sensível (por exemplo, validações extras, ofuscações, checks anti-mod).

## Por que é importante pra você

- Útil quando:
  - Quer entender/contornar inicializações de anticheat.
  - Quer mexer em algo que claramente não veio do C# (ex.: rotinas criptográficas, verificação de integridade, etc.).
- Também pode ser alvo de patch se o dev jogou alguma lógica de “segurança” ali.

**Resumo:** é o segundo alvo em importância. Foca-se nele quando:

- Você suspeita de anticheat/validação.
- Ou quando não encontrou a lógica desejada em `libil2cpp.so`.

---

# 3. libunity.so

## O que é

- O próprio motor Unity em forma de biblioteca nativa.
- Código genérico da engine, compartilhado entre muitos jogos.

## O que costuma ter lá

- Renderização, física, áudio, UI engine, input, gerenciamento de cenas.
- Sistema de objetos, corrotinas, etc.

## Por que costuma ser um problema

- É enorme, muito complexo, e fortemente reutilizado.
- Endereços virtuais muito espaçados → `merged.bin` fica gigante se tentar cobrir todo o range.
- A chance de você precisar mexer diretamente em `libunity.so` pra:
  - Moedas, gemas, energia, blindagem, dano…
  é bem baixa.

## Quando faz sentido olhar pra ele

- Coisas muito específicas de engine:
  - Wallhack/ESP mexendo em frustum/visibilidade.
  - Hacks de física (gravidade global, colisão).
  - Bypasses muito avançados que dependam de entender exatamente como Unity integra com o SO.

**Resumo:** pra seu objetivo atual (mod menu de recursos/jogabilidade), `libunity.so` quase sempre é overkill. Ele pesa, complica o merge, e raramente é o primeiro lugar para procurar lógica de moeda/vida.

---

# 4. Prioridade para o seu fluxo

Considerando tudo isso e a stack que já montamos:

- **Sempre:**
  - Mesclar e analisar `libil2cpp.so_merged.bin`.
- **Geralmente também:**
  - Mesclar `libmain.so_merged.bin` (pra anticheat, colas nativas e casos “estranhos”).
- **Só se realmente precisar:**
  - `libunity.so_merged.bin` — e mesmo assim eu usaria com cuidado, justamente por causa de tamanho e complexidade.

Então, na prática, pra não se afogar:

1. Foca em `libil2cpp.so` como fonte principal das funções que vão pro `re_index.json`.
2. Usa `libmain.so` como apoio quando algo parece nativo/anticheat.
3. Deixa `libunity.so` fora do fluxo padrão, a menos que surja um motivo muito específico.
