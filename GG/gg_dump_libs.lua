gg.require('101.1')
gg.setVisible(false)

local targets = {
  'libmain.so',
  'libunity.so',
  'libil2cpp.so',
  'libxlua.so',
  'libfrida-gadget.so'
}

local pkg = gg.getTargetPackage()
if not pkg or pkg == '' then
  gg.alert('Selecione primeiro o processo do jogo no GameGuardian e rode o script de novo.')
  os.exit()
end

gg.alert('Deixe o jogo exatamente na tela ou ação crítica que você quer capturar (por exemplo depois do login, lobby, ou tela protegida).\n\nQuando estiver pronto, toque OK.')

local mods = {}

gg.setRanges(gg.REGION_CODE_APP | gg.REGION_C_ALLOC | gg.REGION_ANONYMOUS | gg.REGION_OTHER)

for i = 1, #targets do
  local name = targets[i]
  local list = gg.getRangesList(name)
  if list ~= nil and #list > 0 then
    mods[name] = list
  end
end

local items = {}
local keys = {}
for name, _ in pairs(mods) do
  table.insert(items, name)
  table.insert(keys, name)
end

if #items == 0 then
  gg.alert('Nenhum módulo alvo encontrado (libmain/libunity/libil2cpp/libxlua/libfrida-gadget).\n\nVerifique se o jogo está totalmente carregado e tente novamente.')
  os.exit()
end

table.insert(items, 1, 'Dumpar TODOS os módulos alvo')

local choice = gg.choice(items, nil, 'Selecione qual módulo deseja dumpar.\nOs dumps serão salvos como páginas de memória em:\n/sdcard/Download/GG_dumps_' .. pkg)
if not choice then
  os.exit()
end

local outRoot = '/sdcard/Download/GG_dumps_' .. pkg

local function dumpModule(name)
  local rs = mods[name]
  if not rs then
    return
  end
  for i = 1, #rs do
    local r = rs[i]
    local dir = outRoot .. '/' .. name .. '_' .. string.format('%X', r.start)
    gg.dumpMemory(r.start, r['end'], dir)
  end
end

if choice == 1 then
  for name, _ in pairs(mods) do
    dumpModule(name)
  end
  gg.alert('Dump concluído para TODOS os módulos em:\n' .. outRoot)
else
  local name = keys[choice - 1]
  dumpModule(name)
  gg.alert('Dump concluído para ' .. name .. ' em:\n' .. outRoot)
end

os.exit()
