-- LABDEMO：字段均采用网络字节序，识别依赖魔数和完整长度。
local protocol = Proto("labdemo", "UCAS teaching UDP protocol")
local f = {
    magic = ProtoField.string("labdemo.magic", "Magic"),
    version = ProtoField.uint8("labdemo.version", "Version", base.DEC),
    kind = ProtoField.uint8("labdemo.type", "Message type", base.DEC, {[1]="Request", [2]="Response", [3]="Error"}),
    identifier = ProtoField.uint32("labdemo.request_id", "Request ID", base.DEC),
    length = ProtoField.uint16("labdemo.length", "Payload length", base.DEC),
    payload = ProtoField.string("labdemo.payload", "Payload"),
    valid = ProtoField.bool("labdemo.valid", "Valid message"),
    error = ProtoField.string("labdemo.error", "Validation error")
}
protocol.fields = f
protocol.prefs.port = Pref.uint("UDP port", 45990, "Teaching protocol UDP port")
local port = 45990

function protocol.dissector(buffer, pinfo, tree)
    if buffer:len() < 4 or buffer(0,4):string() ~= "LAB1" then return 0 end
    local subtree = tree:add(protocol, buffer())
    subtree:add(f.magic, buffer(0,4))
    if buffer:len() < 12 then
        subtree:add(f.valid, false)
        subtree:add(f.error, "header_truncated")
        return buffer:len()
    end
    subtree:add(f.version, buffer(4,1))
    subtree:add(f.kind, buffer(5,1))
    subtree:add(f.identifier, buffer(6,4))
    subtree:add(f.length, buffer(10,2))
    local version, kind, length = buffer(4,1):uint(), buffer(5,1):uint(), buffer(10,2):uint()
    local problem = nil
    if version ~= 1 then problem = "unsupported_version"
    elseif length > 4096 or buffer:len() ~= 12 + length then problem = "invalid_length"
    elseif kind ~= 1 and kind ~= 2 and kind ~= 3 then problem = "unknown_type" end
    subtree:add(f.valid, problem == nil)
    if problem then
        subtree:add(f.error, problem)
        pinfo.cols.info:append(" LABDEMO invalid: " .. problem)
    else
        pinfo.cols.protocol = "LABDEMO"
        pinfo.cols.info = string.format("Type=%d ID=%d Length=%d", kind, buffer(6,4):uint(), length)
        if length > 0 then subtree:add(f.payload, buffer(12,length)) end
    end
    return buffer:len()
end

local udp = DissectorTable.get("udp.port")
udp:add(port, protocol)
protocol:register_heuristic("udp", function(buffer, pinfo, tree)
    if buffer:len() < 12 or buffer(0,4):string() ~= "LAB1" then return false end
    protocol.dissector(buffer, pinfo, tree)
    return true
end)
function protocol.prefs_changed()
    udp:remove(port, protocol)
    port = protocol.prefs.port
    udp:add(port, protocol)
end
