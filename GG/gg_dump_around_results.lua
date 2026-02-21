gg.require('101.1')
gg.setVisible(false)

local results = gg.getResults(500)
if #results == 0 then
  gg.alert('Nenhum resultado selecionado no GG.')
  os.exit()
end

local pkg = gg.getTargetPackage() or 'unknown'
local radius = 0x1000

local tagInput = gg.prompt(
  {'Nome para este dump de resultados (ex: lobby, batalha1)'}, 
  {os.date('%Y%m%d_%H%M%S')}, 
  {'text'}
)
local dumpTag = os.date('%Y%m%d_%H%M%S')
if tagInput ~= nil and tagInput[1] ~= nil and tagInput[1] ~= '' then
  dumpTag = tagInput[1]
end
dumpTag = dumpTag:gsub('%s+', '_')
dumpTag = dumpTag:gsub('[^%w_%-%.]', '')

local outRoot = '/sdcard/Download/GG_dumps_results_' .. pkg .. '/' .. dumpTag

local logPath = outRoot .. '/index.txt'
os.remove(logPath)

local function writeLog(line)
  local f = io.open(logPath, 'a')
  if f then
    f:write(line .. '\n')
    f:close()
  end
end

gg.alert('Serão dumpados ' .. #results .. ' endereços, cada um com janela de ' .. string.format('0x%X', radius) .. ' bytes para cada lado.')

local frozenItems = {}

for i, r in ipairs(results) do
  local center = r.address
  local from = center - radius
  local to = center + radius
  if from < 0 then
    from = 0
  end
  local dir = outRoot .. '/' .. string.format('%016X', center)
  gg.dumpMemory(from, to, dir)
  writeLog(string.format('addr=0x%016X type=%d file=%s', center, r.flags, dir))
  table.insert(frozenItems, {
    address = center,
    flags = r.flags,
    value = r.value,
    freeze = true,
    name = r.name
  })
end

if #frozenItems > 0 then
  gg.addListItems(frozenItems)
end

gg.alert('Dump ao redor dos resultados concluído em:\n' .. outRoot)
os.exit()
