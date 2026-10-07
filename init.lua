--[[
  ===============================================================================
   No Mod Lock  /  init.lua          （v2 —— 特征串扫描版）
  ===============================================================================

   作用：彻底移除 Noita 因「启用了 mod」而施加的一切限制——
         成就、可解锁内容、本局纪录 / 连胜 / 结算统计。

   -------------------------------------------------------------------------
   v2 相比 v1 的变化
   -------------------------------------------------------------------------

   v1 把补丁地址硬编码在 files/patches.txt 里。后果：Noita 一更新，代码位置
   平移，地址全部错位。虽有原字节校验兜底（不会写坏），但补丁会整体失效。

   v2 改为**特征串扫描**：不记地址，记"这段机器码长什么样"。全局变量地址在
   特征串里一律写成通配（??），因此全局表本身移动也不影响。只要目标函数的
   代码没被改写，位置怎么平移都能找到。

   -------------------------------------------------------------------------
   补的到底是什么（引擎内部）
   -------------------------------------------------------------------------

   引擎有两套互相独立的「因为开了 mod 所以要限制你」的判定。

   【门 1】会话标记
       世界状态实体上 WorldStateComponent 的两个 char 字段：
           +0x120  mods_have_been_active_during_this_run
           +0x121  twitch_has_been_active_during_this_run
       读它的地方很多，而且**无法穷举**——已实证存在把组件指针当函数参数传
       进去、因而不引用全局变量的访问点（0xC42D30 函数把第 3 个参数放进
       edi，然后访问 [edi+0x120] / [edi+0x121]）。

       所以 v2 不去追读取者，而是**堵死写入者**：穷举全 .text 的字节模式后，
       真正能把标志置 1 的只有 2 处，把它们的立即数 01 改成 00 即可。
       写入者一死，所有读取者（含我们找不到的那些）看到的永远是 0。

   【门 2】mod 列表元素个数
       全局 mod 向量（std::vector<ModInfo>，元素 0x60 字节）的
       (end - begin) / 0x60。引擎里 11 处在算这个数；本 mod 补掉其中 8 处
       **消费侧**判定（sub ecx,[begin] → xor ecx,ecx）。

       ⚠ 另外 3 处（0x82E860 / 0x82F1AD / 0x830260）位于 mod 子系统**内部**
         （mod 加载 / 虚拟文件系统 / 菜单），刻意不补：那里计数变成 0 会让
         引擎认为"没有任何 mod"但 mod 内容仍在，状态不一致 → 结算界面卡死
         （已实测踩过这个坑）。

   -------------------------------------------------------------------------
   两层设计
   -------------------------------------------------------------------------

   第一层（功能层）：特征串扫描 + 一次性打补丁，共 11 个站点。
                     **全有或全无** —— 任何一条找不到或校验不符，就整体放弃、
                     一个字节都不写，只写日志。

   第二层（哨兵层）：用「按字段名」这个唯一跨版本的能力**只读**监视门 1 的
                     两个字段。字段恒为 false 时第二层只读不写，零足迹；
                     一旦读到 true 就**先清除、后告警**。它负责兜住：
                       · 旧存档可能带着 1 被载入（那些存档是装本 mod 之前存的）
                       · 无法证明不存在的"经由引擎通用设值接口"的写入路径
                       · 第一层因版本更新失效时，充当版本哨兵

   -------------------------------------------------------------------------
   日志（唯一的告警渠道；游戏内不弹任何提示）
   -------------------------------------------------------------------------

       %USERPROFILE%\AppData\LocalLow\Nolla_Games_Noita\no_mod_lock_log.txt
--]]


-- ============================================================================
--  配置
-- ============================================================================

local LOG_NAME    = "no_mod_lock_log.txt"
local SIG_FILE    = "signatures.txt"
local MOD_PATH    = "mods/no_mod_lock/files/"

local PAGE_EXECUTE_READWRITE = 0x40
local IMAGE_SCN_MEM_EXECUTE  = 0x20000000

-- 第二层轮询间隔（帧）。只做一次字段读取，开销可忽略。
local POLL_EVERY  = 30


-- ============================================================================
--  日志
-- ============================================================================

local function log_dir()
	local up = nil
	pcall( function() up = os.getenv( "USERPROFILE" ) end )
	if up then return up .. "\\AppData\\LocalLow\\Nolla_Games_Noita\\" end
	return nil
end

local function log( msg )
	local line = tostring( msg )
	pcall( function() print( "NO_MOD_LOCK: " .. line ) end )
	local d = log_dir()
	if not d then return end
	pcall( function()
		local f = io.open( d .. LOG_NAME, "a" )
		if f then f:write( line .. "\n" ); f:close() end
	end )
end


-- ============================================================================
--  FFI / PE
-- ============================================================================

local F, k32, baseNum = nil, nil, nil
local u8, u16, u32

-- 判断 32 位无符号值的某一位是否置位（Lua 5.1 没有位运算）
local function has_bit( v, bit )
	if v < 0 then v = v + 4294967296 end
	return math.floor( v / bit ) % 2 == 1
end

local function init_ffi()
	local ok, err = pcall( function()
		F = require( "ffi" )
		F.cdef[[
			void* GetModuleHandleA(const char* lpModuleName);
			int   VirtualProtect(void* lpAddress, size_t dwSize,
			                     uint32_t flNewProtect, uint32_t* lpflOldProtect);
		]]
		k32 = F.load( "kernel32" )
		baseNum = tonumber( F.cast( "uintptr_t", k32.GetModuleHandleA( nil ) ) )

		u8  = function( p ) return F.cast( "uint8_t*",  p )[ 0 ] end
		u16 = function( p ) return F.cast( "uint16_t*", p )[ 0 ] end
		u32 = function( p ) return F.cast( "uint32_t*", p )[ 0 ] end
	end )
	if not ok then
		log( "✗ ffi 初始化失败（是否没开 unsafe mods？）: " .. tostring( err ) )
		return false
	end
	return true
end

-- 定位可执行段：优先名为 .text 的段，否则取第一个带可执行属性的段
local function find_text_section()
	local pe = baseNum + u32( baseNum + 0x3C )
	local nsec = u16( pe + 6 )
	local optSize = u16( pe + 20 )
	local secTable = pe + 24 + optSize

	local fallback = nil
	for i = 0, nsec - 1 do
		local s = secTable + i * 40
		local name = {}
		local k = 0
		while k < 8 do
			local c = u8( s + k )
			if c == 0 then break end
			name[ #name + 1 ] = string.char( c )
			k = k + 1
		end
		name = table.concat( name )

		local virtSize = u32( s + 8 )
		local va       = u32( s + 12 )
		local rawSize  = u32( s + 16 )
		local chars    = u32( s + 36 )
		local size     = virtSize
		if rawSize > size then size = rawSize end

		if name == ".text" then
			return baseNum + va, size, name
		end
		if not fallback and has_bit( chars, IMAGE_SCN_MEM_EXECUTE ) then
			fallback = { va = va, size = size, name = name }
		end
	end
	if fallback then
		return baseNum + fallback.va, fallback.size, fallback.name
	end
	return nil
end


-- ============================================================================
--  特征串解析与扫描
-- ============================================================================

-- 把 "8B0D????????B8AB" 解析成字节数组 + 通配标记
local function decode_sig( hex )
	local bytes, wild, n = {}, {}, 0
	local i = 1
	while i < #hex do
		local two = hex:sub( i, i + 1 )
		n = n + 1
		if two == "??" then
			bytes[ n ] = 0
			wild[ n ] = true
		else
			bytes[ n ] = tonumber( two, 16 )
			wild[ n ] = false
		end
		i = i + 2
	end
	return bytes, wild, n
end

local function bytes_to_str( bytes, from, len )
	local out = {}
	for i = from, from + len - 1 do
		out[ #out + 1 ] = string.char( bytes[ i ] )
	end
	return table.concat( out )
end

-- 两阶段查找：先用「最长无通配段」做 plain 查找（C 速度），再逐字节校验通配位。
-- 返回命中起始位置数组（1-based）；失败时返回 nil + 原因。
local function find_all( textStr, bytes, wild, n )
	local bestOff, bestLen, curOff, curLen = 1, 0, 1, 0
	for i = 1, n do
		if not wild[ i ] then
			if curLen == 0 then curOff = i end
			curLen = curLen + 1
			if curLen > bestLen then bestOff, bestLen = curOff, curLen end
		else
			curLen = 0
		end
	end
	if bestLen < 8 then
		return nil, "锚点过短(" .. bestLen .. ")"
	end

	local anchor = bytes_to_str( bytes, bestOff, bestLen )
	local hits = {}
	local init = 1
	local textLen = #textStr

	while true do
		local s = string.find( textStr, anchor, init, true )
		if not s then break end
		local startPos = s - ( bestOff - 1 )
		if startPos >= 1 and ( startPos + n - 1 ) <= textLen then
			local ok = true
			for i = 1, n do
				if not wild[ i ] and string.byte( textStr, startPos + i - 1 ) ~= bytes[ i ] then
					ok = false
					break
				end
			end
			if ok then hits[ #hits + 1 ] = startPos end
		end
		init = s + 1
	end
	return hits
end

local function read_mod_text( name )
	local t = pcall( ModTextFileGetContent, MOD_PATH .. name )
	if type( t ) == "string" and #t > 0 then return t end
	local out = nil
	pcall( function()
		local f = io.open( MOD_PATH .. name, "r" )
		if f then out = f:read( "*a" ); f:close() end
	end )
	return out
end

local function parse_sig_file( txt )
	local list = {}
	for line in txt:gmatch( "[^\r\n]+" ) do
		local clean = line:gsub( "#.*$", "" ):gsub( "%s", "" )
		if #clean > 0 then
			local sigHex, offStr, newHex, origHex, label =
				clean:match( "^(.-)|(%d+)|(%x+)|([%x%?]+)|(.*)$" )
			if sigHex and #sigHex % 2 == 0 then
				list[ #list + 1 ] = {
					hex = sigHex, off = tonumber( offStr ),
					new = newHex, orig = origHex, label = label,
				}
			else
				log( "  跳过无法解析的行: " .. line )
			end
		end
	end
	return list
end


-- ============================================================================
--  写入工具
-- ============================================================================

local function write_bytes( va, bytes )
	local old = F.new( "uint32_t[1]" )
	local n = #bytes
	local vp = k32.VirtualProtect( F.cast( "void*", va ), n, PAGE_EXECUTE_READWRITE, old )
	pcall( function()
		local p = F.cast( "uint8_t*", va )
		for i = 1, n do p[ i - 1 ] = bytes[ i ] end
	end )
	k32.VirtualProtect( F.cast( "void*", va ), n, old[ 0 ], old )
	return vp
end

local function read_hex( text )
	local out = {}
	for b in text:gmatch( "%x%x" ) do out[ #out + 1 ] = tonumber( b, 16 ) end
	return out
end

local function fmt( bytes )
	local t = {}
	for i = 1, #bytes do t[ #t + 1 ] = string.format( "%02X", bytes[ i ] ) end
	return table.concat( t, " " )
end


-- ============================================================================
--  第一层：特征串扫描 + 一次性打补丁（全有或全无）
-- ============================================================================

local patch_state = "unknown"     -- ok / failed / noffi

local function apply_patches()
	local txt = read_mod_text( SIG_FILE )
	if type( txt ) ~= "string" then
		log( "✗ 读不到 " .. SIG_FILE )
		patch_state = "failed"
		return
	end

	local textVA, textSize, textName = find_text_section()
	if not textVA then
		log( "✗ 找不到可执行段" )
		patch_state = "failed"
		return
	end
	log( "可执行段 " .. tostring( textName ) ..
	     "  VA=0x" .. string.format( "%08X", textVA ) ..
	     "  大小=" .. textSize .. " 字节" )

	-- 整段读进 Lua 字符串，之后用 plain 查找（C 速度）
	local textStr = F.string( F.cast( "uint8_t*", textVA ), textSize )

	local sigs = parse_sig_file( txt )
	log( "载入特征串 " .. #sigs .. " 条" )

	-- ---------------- 阶段 1：全部定位；任何一条不合格就整体放弃 ----------------
	local located = {}
	local bad = 0

	for idx = 1, #sigs do
		local s = sigs[ idx ]
		local bytes, wild, n = decode_sig( s.hex )
		local hits, err = find_all( textStr, bytes, wild, n )

		if not hits then
			log( string.format( "  [失败] [%d] %-24s 扫描失败: %s",
				idx, s.label, tostring( err ) ) )
			bad = bad + 1
		elseif #hits ~= 1 then
			log( string.format( "  [失败] [%d] %-24s 命中 %d 次（要求恰好 1 次）",
				idx, s.label, #hits ) )
			bad = bad + 1
		else
			local va = textVA + ( hits[ 1 ] - 1 ) + s.off
			located[ #located + 1 ] = { s = s, va = va }
			log( string.format( "  [成功] [%d] %-24s 命中 1 次，补丁位置 0x%08X",
				idx, s.label, va ) )
		end
	end

	if bad > 0 then
		log( string.format(
			"[失败] 有 %d 条特征串未通过校验，整体放弃，不写入任何字节", bad ) )
		log( "可能原因：Noita 已更新，目标代码被改写" )
		log( "本 mod 本轮不生效；需要更新 files/signatures.txt" )
		patch_state = "failed"
		return
	end

	-- ---------------- 阶段 2：逐条核对原字节（同样不允许异常） ----------------
	local todo = {}
	for i = 1, #located do
		local e = located[ i ]
		local newB = read_hex( e.s.new )
		local origHex = e.s.orig or ""

		local cur = {}
		for k = 1, #newB do cur[ k ] = u8( e.va + k - 1 ) end

		-- 防线：原字节字段必须与补丁等长。长度不齐会让逐字节比对被静默跳过，
		--      等于"没校验就写"，因此按失败处理（全有或全无）。
		if #origHex ~= #newB * 2 then
			log( string.format(
				"  [失败] %-24s 原字节字段长度 %d != 补丁长度 %d 字节，拒绝",
				e.s.label, #origHex, #newB ) )
			bad = bad + 1
		else
			local isNew = true
			for k = 1, #newB do
				if cur[ k ] ~= newB[ k ] then isNew = false end
			end

			-- 原字节里 ?? 的位置（绝对地址）不参与比对
			local isOrig = true
			local oi = 1
			for k = 1, #newB do
				local two = origHex:sub( oi, oi + 1 )
				if two ~= "??" and cur[ k ] ~= tonumber( two, 16 ) then
					isOrig = false
				end
				oi = oi + 2
			end

			if isNew then
				log( string.format( "  [跳过] %-24s 已是补丁状态", e.s.label ) )
			elseif isOrig then
				todo[ #todo + 1 ] = { e = e, newB = newB, cur = cur }
			else
				log( string.format(
					"  [失败] %-24s 原字节不符，拒绝\n    期望: %s\n    实际: %s",
					e.s.label, origHex, fmt( cur ) ) )
				bad = bad + 1
			end
		end
	end

	if bad > 0 then
		log( string.format( "[失败] 有 %d 条原字节不符，整体放弃，不写入任何字节", bad ) )
		patch_state = "failed"
		return
	end

	-- ---------------- 阶段 3：全部写入 ----------------
	local written, failed = 0, 0
	for i = 1, #todo do
		local t = todo[ i ]
		write_bytes( t.e.va, t.newB )

		local after = {}
		for k = 1, #t.newB do after[ k ] = u8( t.e.va + k - 1 ) end

		local same = true
		for k = 1, #t.newB do
			if after[ k ] ~= t.newB[ k ] then same = false end
		end

		if same then
			written = written + 1
			log( string.format( "  [成功] %-24s 0x%08X  %s -> %s",
				t.e.s.label, t.e.va, fmt( t.cur ), fmt( after ) ) )
		else
			failed = failed + 1
			log( string.format( "  [失败] %-24s 写入失败  %s -> %s",
				t.e.s.label, fmt( t.cur ), fmt( after ) ) )
		end
	end

	if failed > 0 then
		log( string.format( "[失败] 写入阶段有 %d 条失败（成功 %d 条，无法回滚）",
			failed, written ) )
		patch_state = "failed"
	else
		log( string.format( "第一层完成：共写入 %d 条补丁，另有 %d 条已是补丁状态",
			written, #located - #todo ) )
		patch_state = "ok"
	end
end


-- ============================================================================
--  第二层：门 1 字段哨兵（按字段名，只读监视；读到 true 才清除）
-- ============================================================================

local FLAG_NAMES = {
	"mods_have_been_active_during_this_run",
	"twitch_has_been_active_during_this_run",
}

local sentinel_warned = false

local function poll_flags()
	pcall( function()
		local we = GameGetWorldStateEntity()
		if not we or we == 0 then return end
		local comp = EntityGetFirstComponentIncludingDisabled( we, "WorldStateComponent" )
		if not comp or comp == 0 then return end

		for i = 1, #FLAG_NAMES do
			local name = FLAG_NAMES[ i ]
			local v = ComponentGetValue2( comp, name )
			if v then
				-- 先清除，再告警（告警只进日志，游戏内不弹任何提示）
				ComponentSetValue2( comp, name, false )
				log( string.format( "哨兵：字段 %s 被置位，已清除。", name ) )
				if not sentinel_warned then
					sentinel_warned = true
					log( "可能来源：旧存档载入 / 其它 mod 直接设置 / 第一层补丁未生效" )
					if patch_state ~= "ok" then
						log( "第一层本轮未成功，本字段却被置位，当前版本很可能不受支持" )
					end
				end
			end
		end
	end )
end


-- ============================================================================
--  生命周期
-- ============================================================================

local frame = 0

-- 启动提示：每个游戏进程只弹一次，内容反映第一层的**真实**结果
local announced = false

local function announce_once()
	if announced then return end
	announced = true

	local msg
	if patch_state == "ok" then
		msg = "no_mod_lock 已正常启动\n\n" ..
		      "逐条写入记录见日志：%appdata%\\..\\LocalLow\\Nolla_Games_Noita\\" .. LOG_NAME
	elseif patch_state == "noffi" then
		msg = "no_mod_lock 启动失败：无法取得 FFI 权限\n\n" ..
		      "请在 Mods 设置里开启「Unsafe mods（不安全的 mod）」，然后重启游戏\n" ..
		      "当前状态下本 mod 不产生任何效果"
	else
		msg = "no_mod_lock 启动异常：代码补丁未通过校验\n\n" ..
		      "可能原因：Noita 已更新，目标代码被改写，本次没有写入任何字节\n" ..
		      "详情见日志：%appdata%\\..\\LocalLow\\Nolla_Games_Noita\\" .. LOG_NAME
	end

	pcall( function() GamePrintImportant( "No Mod Lock", msg ) end )
	log( "已弹出启动提示（patch_state=" .. tostring( patch_state ) .. "）" )
end

function OnModPreInit()
	log( "" )
	log( "############ no_mod_lock 初始化############" )
	if init_ffi() then
		log( "主模块基址 = 0x" .. string.format( "%08X", baseNum ) )
		apply_patches()
	else
		patch_state = "noffi"
	end
end

function OnWorldInitialized()
	announce_once()       -- 启动提示（每个游戏进程只弹一次）
	poll_flags()          -- 世界刚建立时查一次（旧存档可能在此时带毒进来）
end

function OnPlayerSpawned( player_entity )
	poll_flags()
end

function OnWorldPreUpdate()
	frame = frame + 1
	if frame % POLL_EVERY == 0 then
		poll_flags()
	end
end

-- 以下三个是**额外的采样点**，用来覆盖 OnWorldPreUpdate 不会被调用的时机
-- （帧尾、暂停中、暂停状态切换）。它们同样只"读到 true 才写"，
-- 不改变"触发式修改"的性质，只是让异常更早被发现。
-- 加齐这三点后，v2 的 Lua 覆盖范围与 v1 的 unrestrict_test 完全一致。
function OnWorldPostUpdate()
	poll_flags()
end

function OnPausePreUpdate()
	poll_flags()
end

function OnPausedChanged( is_paused )
	poll_flags()
end
