-- Determine if this is running on pre-3.2.0 firmware.
LEGACY = not system.exists("route.group_new")

-- Determine if this is running >= 3.4.3 firmware.
FWVER_GE_3_4_3 = pcall(function() x = route.group_new().ping_src_addr end)

-- Determine if this is running >= 3.6.0 firmware.
FWVER_GE_3_6_0 = pcall(function() x = route.group_new().poison_delay_secs end)

-- Determine if this is running >= 3.6.0 firmware.
FWVER_GE_3_6_1 = pcall(function() x = wan.new('uart', 'pvs8').time end)

-- Determine if this is running >= 3.8.1 firmware.
FWVER_GE_3_8_1= pcall(function() x = mlme.restore_opt end)

-- Determine if this is running >= 4.6.0 firmware.
FWVER_GE_4_6_0= pcall(function() x = trap.server_public_key end)

-- Some utilities.
function is_set(val)
    if val and val ~= "" then
        return true
    else
        return false
    end
end

function is_true(val)
    return is_set(val) and val ~= 0
end

-- If a simple (non-failover) vars script is being used, convert its exported
-- globals to the complex table format.
if not WAN_CFGS or not WAN_CFGS[1] then
    WAN_CFGS = {
        function ()
            if WAN_ITF_TYPE and WAN_ITF_TYPE:lower() == 'ethernet' and
                    not MODEM_TYPE then
                MODEM_TYPE = 'ETH_GENERIC'
            end

            WAN_ITFS = { {
                -- [Complex] =          [simple]
                ITF_TYPE =              WAN_ITF_TYPE,
                MODEM_TYPE =            MODEM_TYPE,
                PORT =                  WAN_PORT            or 0,
                MODEM_PORT =            MODEM_PORT,
                DHCP =                  WAN_DHCP            or WAN_DHCP_EN,
                ETH_LOCAL_IPV4 =        ETH_LOCAL_IPV4      or WAN_LOCAL_IPV4,
                ETH_DEFAULT_ROUTER =    ETH_DEFAULT_ROUTER  or WAN_DEFAULT_ROUTER,
                MAX_STARTS =            WAN_MAX_STARTS,
                PPP_LOCAL_IPV4 =        PPP_LOCAL_IPV4,
                PPP_REMOTE_IPV4 =       PPP_REMOTE_IPV4,
                PPP_CHAP_USER =         PPP_CHAP_USER       or PPP_CHAPUSER,
                PPP_CHAP_PASSWD =       PPP_CHAP_PASSWD	    or PPP_CHAPPW,
                PPP_ROUTE_IPV4 =        PPP_ROUTE_IPV4,
                GPRS_APN =              WAN_GPRS_APN,
                WD_SCRIPT =             WD_SCRIPT,
                MUX =                   WAN_MUX,
                TIME =                  WAN_TIME,

                GROUPS = { {
                    -- [Complex] =      [simple]
                    PINGER_ADDR =       WAN_PINGER_ADDR,
                    PINGER_SRC_ADDR =   WAN_PINGER_SRC_ADDR,
                    PINGER_TEST_ITVL =  WAN_PINGER_TEST_ITVL,
                    PINGER_ITVL =       WAN_PINGER_ITVL,
                    PINGER_SIZE =       WAN_PINGER_SIZE,
                    PINGER_COUNT =      WAN_PINGER_COUNT,
                    PINGER_FAIL_COUNT = WAN_PINGER_FAIL_COUNT,
                    PINGER_BACKOFF =    WAN_PINGER_BACKOFF,
                    POISON_DELAY_SECS = POISON_DELAY_SECS,
                    POISON_TX_MODE =    POISON_TX_MODE,
                } }
            } }

            if DA_GROUP_PINGER and DA_TUNNELS then
                if not WAN_ITFS[1].GROUPS[1]["ROUTES"] then
                    WAN_ITFS[1].GROUPS[1]["ROUTES"] = { { ADDR = "::/0",} }
                end
                table.insert(WAN_ITFS[1].GROUPS,DA_GROUP_PINGER)
            end

            TUNNELS = { {
                -- [Complex] =          [simple]
                ENTRYPOINT =            ENTRYPOINT          or TUN64_V4SRC,
                ENDPOINT =              ENDPOINT            or TUN64_V4DST,
                SRC =                   SRC                 or TUN64_V6SRC,
                DST =                   DST                 or TUN64_V6PREFIX,
                IPSEC_AUTH_ALG =        IPSEC_AUTH_ALG,
                IPSEC_ENCRYPT_ALG =     IPSEC_ENCRYPT_ALG,
                IPSEC_SPI_OUT =         IPSEC_SPI_OUT,
                IPSEC_AUTH_KEY_OUT =    IPSEC_AUTH_KEY_OUT,
                IPSEC_ESP_KEY_OUT =     IPSEC_ESP_KEY_OUT,
                IPSEC_SPI_IN =          IPSEC_SPI_IN,
                IPSEC_AUTH_KEY_IN =     IPSEC_AUTH_KEY_IN,
                IPSEC_ESP_KEY_IN =      IPSEC_ESP_KEY_IN,
                IPSEC_LIFE_SECS =       IPSEC_LIFE_SECS,
                IPSEC_LIFE_KBYTES =     IPSEC_LIFE_KBYTES,
                IPSEC_IKE_HASH =        IPSEC_IKE_HASH,
                IPSEC_IKE_ENCRYPT =     IPSEC_IKE_ENCRYPT,
                IPSEC_IKE_SHAREDKEY =   IPSEC_IKE_SHAREDKEY,
                IPSEC_IKE_DHGROUP =     IPSEC_IKE_DHGROUP,
                IPSEC_IKE_LIFE_SECS =   IPSEC_IKE_LIFE_SECS,
                IPSEC_IKE_LIFE_KBYTES = IPSEC_IKE_LIFE_KBYTES,
                NATT_INTERVAL =         NATT_INTERVAL,
                GRE =                   GRE,
            } }

            if DA_GROUP_PINGER and DA_TUNNELS then
                for i = 1,table.maxn(DA_TUNNELS) do
                    table.insert(TUNNELS,DA_TUNNELS[i])
                end
                if FWVER_GE_3_6_1 and not is_set(TUN64_MAX_TUNNELS) and tun64.max_tunnels < table.getn(TUNNELS) + 1 then
                    tun64.max_tunnels = table.getn(TUNNELS) + 1
                end
            end

            -- [Complex] =              [simple]
            WAN_CALL_HOME_SERVERS =     WAN_CALL_HOME_SERVERS
            WAN_CALL_HOME_RETRIES =     WAN_CALL_HOME_RETRIES

            RF_V6_PREFIX =              RF_V6_PREFIX
            RF_V4_ADDRESSES =           { RF_V4_ADDRESS }

            NTP_SERVER =                NTP_SERVER
            NTP_MODE =                  NTP_MODE

            if DA_ADDITIONAL_CFG then
                DA_ADDITIONAL_CFG()
            end

        end
    }
else
    --Mix complex and simple to override WAN_MODE
    if is_set(WAN_MODE) and WAN_MODE == "mesh" then
        OVERRIDE_WAN_MODE = WAN_MODE
    end
end

-- ----------------------------------------------------------
-- Select failover stage.
-- ----------------------------------------------------------
if LEGACY then
    -- pre-3.2.0 doesn't support failover; just execute the first stage.
    WAN_CFGS[1]()
else
    if failover.stage < 1 or failover.stage > table.maxn(WAN_CFGS) then
        failover.stage = 1
    end
    WAN_CFGS[failover.stage]()
end
--override the wan mode from complex structure
if is_set(OVERRIDE_WAN_MODE) and OVERRIDE_WAN_MODE == "mesh" then
    WAN_MODE = OVERRIDE_WAN_MODE
end
-- ----------------------------------------------------------
-- Set WAN mode
-- ----------------------------------------------------------
if not LEGACY then
    if is_set(WAN_MODE) then
        wan.mode = WAN_MODE
    end
end

-- ----------------------------------------------------------
-- Prune incomplete config elements.
-- ----------------------------------------------------------
if (not WAN_ITFS) or (is_set(wan.mode) and wan.mode == "mesh") then
    WAN_ITFS = {}
end
for i = table.maxn(WAN_ITFS),1,-1 do
    if not is_set(WAN_ITFS[i].ITF_TYPE) or
       not is_set(WAN_ITFS[i].MODEM_TYPE) or
       not is_set(WAN_ITFS[i].PORT) then

        table.remove(WAN_ITFS, i)
    else
        -- Each interface requires at least one route group.
        if not WAN_ITFS[i].GROUPS or not WAN_ITFS[i].GROUPS[1] then
            -- Just add the default group (all routes, no pinger).
            WAN_ITFS[i].GROUPS = { { } }
        end
    end
end

if not TUNNELS then
    TUNNELS = {}
end
for i = table.maxn(TUNNELS),1,-1 do
    tun = TUNNELS[i]

    -- Prefer new generic names, but accept old 6-in-4 names.
 -- [cur]             [new]                [old]               [default]
    tun.SRC         = tun.SRC           or tun.V6SRC
    tun.DST         = tun.DST           or tun.V6PREFIX     or "::/0"
    tun.ENTRYPOINT  = tun.ENTRYPOINT    or tun.V4SRC
    tun.ENDPOINT    = tun.ENDPOINT      or tun.V4DST

    if not is_set(tun.ENDPOINT) then
        table.remove(TUNNELS, i)
    end
end

if not RF_V4_ADDRESSES then
    RF_V4_ADDRESSES = { }
end
for i = table.maxn(RF_V4_ADDRESSES),1,-1 do
    if not RF_V4_ADDRESSES[i] then
        table.remove(RF_V4_ADDRESSES, i)
    end
end

-- ----------------------------------------------------------
-- WAN interface bringup
-- ----------------------------------------------------------
if LEGACY then
    -- pre-3.2.0: only one WAN_ITF interface allowed.
    if WAN_ITFS then
        WAN_ITF = WAN_ITFS[1]
    end
    if WAN_ITF then
        ---- WAN_ITF interface bringup
        if WAN_ITF.ITF_TYPE:lower() ~= "ethernet" then
            WAN_PORT_NAME = "uart"..WAN_ITF.PORT
            ARG2 = WAN_ITF.MODEM_TYPE
        else
            WAN_PORT_NAME = "eth0"
            WAN_PORT = eth0
            if is_true(WAN_ITF.DHCP) then
                ARG2 = "dhcp"
            else
                ARG2 = "no_dhcp"
            end
        end
    end

    if WAN_PORT_NAME and ARG2 then
        wan0 = wan.new(WAN_PORT_NAME, ARG2)
        if is_set(WAN_ITF.MAX_STARTS) then
            wan0.max_starts = WAN_ITF.MAX_STARTS
        end
        wan.enable(wan0)
    end
else
    for _,WAN_ITF in ipairs(WAN_ITFS) do
        local port_type, uart
        if WAN_ITF.ITF_TYPE == 'serial' then
            port_type = "uart"
        else
            port_type = "eth"
        end

        wan_itf = wan.new(port_type, WAN_ITF.MODEM_TYPE)
        wan_itf.port = WAN_ITF.PORT
        wan_itf.modem_port = WAN_ITF.MODEM_PORT
        if is_set(WAN_ITF.MAX_STARTS) then
            wan_itf.max_starts = WAN_ITF.MAX_STARTS
        end
        wan_itf.dhcp = is_true(WAN_ITF.DHCP)
        wan_itf.gprs_apn = WAN_ITF.GPRS_APN
        if FWVER_GE_3_4_3 and WAN_ITF.MUX ~= nil then
            wan_itf.mux = is_true(WAN_ITF.MUX)
        end
        if FWVER_GE_3_6_1 and WAN_ITF.TIME ~= nil then
            wan_itf.time = is_true(WAN_ITF.TIME)
        end
        wan.enable(wan_itf)

        WAN_ITF.obj = wan_itf
    end
end

-- ----------------------------------------------------------
-- Call Home Configuration
-- ----------------------------------------------------------
if is_set(WAN_CALL_HOME_SERVERS) and (is_set(wan.mode) and wan.mode ~= "mesh") then
    wan.call_home.servers = WAN_CALL_HOME_SERVERS
    if is_set(WAN_CALL_HOME_RETRIES) then
        wan.call_home.retries = WAN_CALL_HOME_RETRIES
    end
    wan.call_home.enable()
end

if is_set(ROUTING) then
    srt.on = ROUTING
end

-- Make sure a vars script was executed prior to this script.
if table.maxn(WAN_ITFS) == 0            and
   table.maxn(TUNNELS) == 0             and
   not is_set(WAN_CALL_HOME_SERVERS)    and
   not is_set(WAN_MODE)                 then

    error("No WAN interfaces, tunnels, call home servers, or WAN mode; " ..
          "vars script not executed?")
end

-- ----------------------------------------------------------
-- Gridscape Configuration
-- ----------------------------------------------------------

if is_set(MLME_NETWORK_ID) then
    mlme.network_id = MLME_NETWORK_ID
end

if is_set(MLME_IGNORE_PROM_NETWORK_ID) then
    mlme.ignore_prom_network_id = MLME_IGNORE_PROM_NETWORK_ID
end
if FWVER_GE_3_6_1 and is_set(RIP_V6_ON) then
    rip.v6_on = RIP_V6_ON
end
--Parameter that only valid when device is AP
if not LEGACY and is_set(wan.mode) and wan.mode ~= "mesh" then
    if is_set(MLME_DEVICE_INFO) then
        mlme.device_info = MLME_DEVICE_INFO
    end
end

if is_set(CONF_SRT_QUICK_RESTORE) and FWVER_GE_3_8_1 then
    srt.quick_restore = CONF_SRT_QUICK_RESTORE
end

if FWVER_GE_3_6_1 and is_set(TUN64_MAX_TUNNELS) then
    tun64.max_tunnels = TUN64_MAX_TUNNELS
end

if FWVER_GE_3_6_1 and is_set(SRT_HIPRIO) then
    srt.hiprio = SRT_HIPRIO
end

if FWVER_GE_3_6_1 and is_set(RIP_ON) then
    rip.on = RIP_ON
end

if FWVER_GE_3_6_1 and is_set(MFP_PROTO_ADDR) then
    mfp.proto_addr = MFP_PROTO_ADDR
end
