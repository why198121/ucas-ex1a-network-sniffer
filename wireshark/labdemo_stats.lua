-- Listener 独立统计请求与响应。重复解析按包号去重，重新载入时清除状态。
local request_type = Field.new("labdemo.type")
local request_id = Field.new("labdemo.request_id")
local valid_field = Field.new("labdemo.valid")
local listener = Listener.new("frame", "labdemo", true)
local seen, pending, requests, responses, errors, invalid, duplicates, total_rtt, pairs_count, last_time, limited

local function reset()
    seen, pending = {}, {}
    requests, responses, errors, invalid, duplicates, total_rtt, pairs_count, last_time = 0, 0, 0, 0, 0, 0, 0, 0
    limited = false
end
listener.reset = reset
reset()

local function endpoint(address, port)
    return tostring(address) .. ":" .. tostring(port)
end

function listener.packet(pinfo, buffer)
    if seen[pinfo.number] then return end
    if pinfo.number > 100000 then limited = true; return end
    seen[pinfo.number] = true
    local value = valid_field()
    if not value or not value.value then invalid = invalid + 1; return end
    local kind, identifier = request_type(), request_id()
    if not kind or not identifier then return end
    kind, identifier = tonumber(kind.value), tostring(identifier.value)
    local timestamp = tonumber(pinfo.abs_ts)
    last_time = math.max(last_time, timestamp)
    local source = endpoint(pinfo.src, pinfo.src_port)
    local destination = endpoint(pinfo.dst, pinfo.dst_port)
    if kind == 1 then
        requests = requests + 1
        local key = source .. ">" .. destination .. "/" .. identifier
        if pending[key] then duplicates = duplicates + 1
        else pending[key] = timestamp end
    else
        responses = responses + 1
        if kind == 3 then errors = errors + 1 end
        local key = destination .. ">" .. source .. "/" .. identifier
        if pending[key] then
            local rtt = timestamp - pending[key]
            if rtt >= 0 then total_rtt = total_rtt + rtt; pairs_count = pairs_count + 1 end
            pending[key] = nil
        end
    end
end

local function report()
    local timeout, waiting = 0, 0
    for _, timestamp in pairs(pending) do
        if last_time - timestamp >= 2 then timeout = timeout + 1 else waiting = waiting + 1 end
    end
    return string.format("LABDEMO_STATS requests=%d responses=%d pairs=%d errors=%d invalid=%d duplicates=%d timeout=%d pending=%d mean_rtt_ms=%s limited=%s",
        requests, responses, pairs_count, errors, invalid, duplicates, timeout, waiting,
        pairs_count > 0 and string.format("%.6f", total_rtt * 1000 / pairs_count) or "unknown", tostring(limited))
end

function listener.draw()
    if not gui_enabled() then print(report()) end
end
if gui_enabled() then
    register_menu("UCAS/LABDEMO request response statistics", function()
        retap_packets()
        local window = TextWindow.new("LABDEMO request response statistics")
        window:set(report())
    end, MENU_STAT_GENERIC)
end
