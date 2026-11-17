local source = debug.getinfo(1, "S").source:sub(2)
local directory = source:match("^(.*[/\\])")
local json = dofile(directory .. "../wireshark/vendor/dkjson.lua")
local arguments = {...}
local input = assert(io.open(arguments[1], "r"))
local config = assert(json.decode(input:read("*a")))
input:close()
local pid = Field.new("labproc.pid")
local stream = Field.new("tcp.stream")
local observer = Listener.new("frame", nil, true)
local frames, matching, streams, applied = {}, {}, {}, false
function observer.packet(info)
    frames[info.number] = true
    for _, value in ipairs({pid()}) do
        if tonumber(value.value) == config.pid then
            matching[info.number] = true
            local connection = stream()
            if connection then streams[tostring(connection.value)] = true end
        end
    end
end
function observer.draw()
    local loaded, matched, identifiers = 0, 0, {}
    for _ in pairs(frames) do loaded = loaded + 1 end
    if loaded == config.packets and not applied then
        applied = true
        set_filter("labproc.pid == " .. config.pid)
        apply_filter()
    end
    for _ in pairs(matching) do matched = matched + 1 end
    for identifier in pairs(streams) do identifiers[#identifiers + 1] = identifier end
    table.sort(identifiers)
    local output = assert(io.open(config.result, "w"))
    output:write(json.encode({filter=get_filter(), loaded=loaded, matched=matched, streams=identifiers, applied=applied}))
    output:close()
end
