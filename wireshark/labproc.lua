-- JSON 仅作为数据读取。捕获文件摘要、逐包摘要、时间和原始编号共同防止误配。
local source = debug.getinfo(1, "S").source:sub(2)
local directory = source:match("^(.*[/\\])") or "./"
local json = dofile(directory .. "vendor/dkjson.lua")
local sha = dofile(directory .. "vendor/sha2.lua")
local protocol = Proto("labproc", "UCAS local process observations")
local frame_time = Field.new("frame.time_epoch")
local f = {
    pid = ProtoField.uint32("labproc.pid", "Local PID", base.DEC),
    name = ProtoField.string("labproc.name", "Process name"),
    status = ProtoField.string("labproc.status", "Association status"),
    session = ProtoField.string("labproc.session", "Capture session UUID"),
    original = ProtoField.uint32("labproc.original_number", "Original capture number", base.DEC),
    sample = ProtoField.string("labproc.sample_ns", "Connection table sample (ns)"),
    associated = ProtoField.string("labproc.associated_ns", "Association time (ns)"),
    created = ProtoField.string("labproc.created", "Process creation time (Unix seconds)"),
    local_endpoint = ProtoField.string("labproc.local", "Observed local endpoint"),
    reason = ProtoField.string("labproc.reason", "Validation / association detail")
}
protocol.fields = f
protocol.prefs.metadata = Pref.string("Metadata JSON", "", "Absolute path to exported .pcap.labproc.json")
protocol.prefs.capture = Pref.string("Paired PCAP", "", "Absolute path to the PCAP paired with the metadata")
local manifest, problem, checked, seen, count, invalid, verified

local function reset()
    manifest, problem, checked, seen, count, invalid, verified = nil, nil, false, {}, 0, false, false
end
protocol.init = reset
protocol.prefs_changed = reset
reset()

local function hash_file(path)
    local handle, message = io.open(path, "rb")
    if not handle then return nil, message end
    local append, size = sha.sha256(), 0
    while true do
        local part = handle:read(65536)
        if not part then break end
        size = size + #part
        if size > 268435456 then handle:close(); return nil, "capture_size_limit" end
        append(part)
    end
    handle:close()
    return append()
end

local function load_manifest()
    checked = true
    if protocol.prefs.metadata == "" or protocol.prefs.capture == "" then
        problem = "unknown_no_metadata"
        return
    end
    local handle = io.open(protocol.prefs.metadata, "rb")
    if not handle then problem = "metadata_unreadable"; return end
    local content = handle:read(67108865)
    handle:close()
    if not content or #content > 67108864 then problem = "metadata_size_limit"; return end
    local decoded, position, message = json.decode(content, 1, nil)
    if message or type(decoded) ~= "table" or content:sub(position):match("%S") then
        problem = "invalid_metadata_json"; return
    end
    if decoded.schema ~= 1 or type(decoded.session_id) ~= "string" or type(decoded.packets) ~= "table"
        or decoded.packet_count ~= #decoded.packets or type(decoded.pcap_sha256) ~= "string" then
        problem = "invalid_metadata_schema"; return
    end
    local digest, why = hash_file(protocol.prefs.capture)
    if not digest or digest ~= decoded.pcap_sha256 then problem = "capture_hash_mismatch: " .. (why or "SHA256"); return end
    for _, item in ipairs(decoded.packets) do
        if type(item) ~= "table" or type(item.sha256) ~= "string" or type(item.timestamp_ns) ~= "string"
            or type(item.caplen) ~= "number" or type(item.wirelen) ~= "number" or type(item.original_number) ~= "number"
            or type(item.process) ~= "table" or type(item.process.status) ~= "string" or type(item.process.owners) ~= "table" then
            problem = "invalid_packet_metadata"; return
        end
        for _, owner in ipairs(item.process.owners) do
            if type(owner.pid) ~= "number" or owner.pid < 1 or owner.pid > 4294967295 or owner.pid % 1 ~= 0
                or type(owner.name) ~= "string" or type(owner.created) ~= "number"
                or type(owner.sample_ns) ~= "string" or type(owner["local"]) ~= "string" then
                problem = "invalid_process_metadata"; return
            end
        end
    end
    manifest = decoded
end

function protocol.dissector(buffer, pinfo, tree)
    if not checked then load_manifest() end
    local subtree = tree:add(protocol)
    if not manifest then subtree:add(f.status, problem or "unknown_no_metadata"); return end
    local number = pinfo.number
    local item = manifest.packets[number]
    local instant = frame_time().value
    local timestamp = string.format("%.0f%09d", instant.secs, instant.nsecs)
    if not item or item.caplen ~= buffer:len() or item.wirelen ~= pinfo.len
        or item.timestamp_ns ~= timestamp or item.sha256 ~= sha.sha256(buffer:raw()) then
        invalid, verified = true, false
    elseif not seen[number] then
        seen[number] = true
        count = count + 1
    end
    if invalid then subtree:add(f.status, "pairing_mismatch"); return end
    if count == manifest.packet_count then verified = true end
    -- 第一遍收集完整有序文件的证据；PID 仅在重复解析时输出。
    -- TShark 使用 -2 -R "frame.number >= 1"，保证第一遍实际创建协议树。
    -- Wireshark 在完整载入后筛选或从菜单重新解析。
    if not verified or not pinfo.visited then
        subtree:add(f.status, "pending_full_capture_validation")
        return
    end
    subtree:add(f.session, manifest.session_id)
    subtree:add(f.original, item.original_number)
    subtree:add(f.status, item.process.status)
    if item.process.reason then subtree:add(f.reason, item.process.reason) end
    if item.process.associated_ns then subtree:add(f.associated, item.process.associated_ns) end
    for _, owner in ipairs(item.process.owners) do
        local child = subtree:add(protocol, "Local process: " .. owner.name)
        child:add(f.pid, owner.pid)
        child:add(f.name, owner.name)
        child:add(f.created, tostring(owner.created))
        child:add(f.sample, owner.sample_ns)
        child:add(f.local_endpoint, owner["local"])
    end
end
register_postdissector(protocol, true)

if gui_enabled() then
    register_menu("UCAS/Refresh process fields", function()
        -- 通过重新应用过滤触发重复解析，保留本次完整文件校验状态。
        local original = get_filter()
        set_filter("frame.number >= 1")
        apply_filter()
        set_filter(original)
        apply_filter()
        local window = TextWindow.new("UCAS process pairing")
        window:set(problem or (invalid and "pairing_mismatch") or
            (verified and "Validated complete capture. Process fields are available on redissection.") or
            ("Pending: " .. count .. " validated frames."))
    end, MENU_TOOLS_UNSORTED)
end
