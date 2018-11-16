--  *** Defined in init script: ***
-- function is_set(val)
-- function is_true(val)
-- LEGACY
-- FWVER_GE_3_4_3
-- FWVER_GE_3_6_0
-- FWVER_GE_3_6_1
-- FWVER_GE_3_8_1
-- FWVER_GE_4_6_0
--  ***

-- Utilities

-- Add val to set if it isn't already present (according to its '==' operator).
function set_insert(set, val)
    for _,elem in ipairs(set) do
        -- metatable hack required due to a 3.0 flow_rule.__eq bug.
        mt = getmetatable(elem)
        if is_true(mt.__eq(elem, val)) then
            return elem
        end
    end

    table.insert(set, val)
    return val
end

-- Collect unique IPsec elements in these global sets.  They get written
-- After they have all been collected.
selcrits = { }
policies = { }
rules = { }
ike_pols = { }
ike_transes = { }
ike_rules = { }
sas = { }

function fwall_add_one(tun)
    local do_ike =
        is_set(tun.ENTRYPOINT)              and
        is_set(tun.ENDPOINT)                and
        is_set(tun.IPSEC_IKE_SHAREDKEY)     and
        is_set(tun.IPSEC_IKE_ENCRYPT)       and
        is_set(tun.IPSEC_IKE_HASH)          and
        is_set(tun.IPSEC_IKE_DHGROUP)       and
        is_set(tun.IPSEC_AUTH_ALG)          and
        is_set(tun.IPSEC_ENCRYPT_ALG)

    local do_ipsec =
        not do_ike                          and
        is_set(tun.ENDPOINT)                and
        is_set(tun.IPSEC_AUTH_ALG)          and
        is_set(tun.IPSEC_ENCRYPT_ALG)       and
        is_set(tun.IPSEC_SPI_OUT)           and
        is_set(tun.IPSEC_AUTH_KEY_OUT)      and
        is_set(tun.IPSEC_ESP_KEY_OUT)       and
        is_set(tun.IPSEC_SPI_IN)            and
        is_set(tun.IPSEC_AUTH_KEY_IN)       and
        is_set(tun.IPSEC_ESP_KEY_IN)

    local ipsec_encrypt = do_ike or do_ipsec

    local ike_rule = nil
    if do_ike then
        -- IKE Policy
        local ike_pol = fwall.ike_policy_new()
        if is_set(tun.IPSEC_ENDPOINT) then
            ike_pol.remote_addr = tun.IPSEC_ENDPOINT.."/32"
        else
            ike_pol.remote_addr = tun.ENDPOINT.."/32"
        end
        ike_pol.local_addr = "dynamic_inet"
        ike_pol.local_port = 500
        ike_pol.remote_port = 500
        ike_pol.protocol = 17
        ike_pol.initiator = true
        ike_pol.responder = true
        ike_pol.aggr_mode = true
        ike_pol.key = tun.IPSEC_IKE_SHAREDKEY
        ike_pol.dpd_mode = "ondemand"
        ike_pol.dpd_wmetric = 120
        ike_pol.dpd_retrans_delay = 10000
        ike_pol.dpd_retrans_limit = 12

        if is_set(tun.NATT_INTERVAL) then
            ike_pol.natt_itvl = tun.NATT_INTERVAL
            ike_pol.local_port = 4500
            ike_pol.remote_port = 4500
        end

        ike_pol = set_insert(ike_pols, ike_pol)

        -- IKE Transform
        local ike_trans = fwall.ike_transform_new()
        ike_trans.enc = tun.IPSEC_IKE_ENCRYPT
        if is_set(tun.IPSEC_IKE_ENCRYPTLEN) then
            ike_trans.enc_keylen = tun.IPSEC_IKE_ENCRYPTLEN
        end
        ike_trans.hash = tun.IPSEC_IKE_HASH
        ike_trans.auth = "sharedkey"
        ike_trans.dhgroup = tun.IPSEC_IKE_DHGROUP
        if is_set(tun.IPSEC_IKE_LIFE_SECS) then
            ike_trans.life_secs = tun.IPSEC_IKE_LIFE_SECS
        end
        if is_set(tun.IPSEC_IKE_LIFE_KBYTES) then
            ike_trans.life_kbytes = tun.IPSEC_IKE_LIFE_KBYTES
        else
            ike_trans.life_kbytes = 32768
        end
        ike_trans = set_insert(ike_transes, ike_trans)


        -- IKE Rule
        ike_rule = fwall.ike_rule_new()
        ike_rule.policy = ike_pol
        ike_rule.transforms = { ike_trans }
        ike_rule = set_insert(ike_rules, ike_rule)
    end

    -- Selection criteria defines the traffic to be allowed/denied/encrypted.
    -- "Catch-all" selector for all remaining traffic.
    selcrit_all = fwall.selcrit_new()
    selcrit_all.local_addr = "0.0.0.0/0"
    selcrit_all.remote_addr = "0.0.0.0/0"
    selcrit_all.local_port = "*"
    selcrit_all.remote_port = "*"
    selcrit_all.protocol = "*"
    selcrit_all = set_insert(selcrits, selcrit_all)

    if ipsec_encrypt then
        -- Determine local network address.
        local selcrit_tun_lcl_nwk_address = nil
        local selcrit_to_us_lcl_nwk_address = nil
        if do_ike then
            -- "Bogus" v4 address for 6-in-4 / 4-in-4 setup.
            selcrit_tun_lcl_nwk_address = tun.ENTRYPOINT.."/32"
            selcrit_to_us_lcl_nwk_address = "dynamic_inet"
        else
            if is_set(tun.ENTRYPOINT) then
                selcrit_tun_lcl_nwk_address = tun.ENTRYPOINT.."/32"
            else
                selcrit_tun_lcl_nwk_address = "dynamic_inet"
            end
            -- Selcrits use the same local address when no bogus entrypoint.
            selcrit_to_us_lcl_nwk_address = selcrit_tun_lcl_nwk_address
        end

        -- Determine entrypoint address.
        local selcrit_lcl_itf_address
        if do_ike or not is_set(tun.ENTRYPOINT) then
            selcrit_lcl_itf_address = "dynamic_inet"
        else
            selcrit_lcl_itf_address = tun.ENTRYPOINT.."/32"
        end

        -- Selector for tunnel traffic
        selcrit_tunnel = fwall.selcrit_new()
        selcrit_tunnel.local_addr = selcrit_tun_lcl_nwk_address

        if is_true(tun.GRE) then
            -- Generic Routing Encapsulation.
            selcrit_tunnel.protocol = 47
        elseif is_set(tun.DST) then
            if string.find(tun.DST, ":") then
                -- IPv6 Encapsulation.
                selcrit_tunnel.protocol = 41
            else
                -- IP-Within-IP (encapsulation).
                selcrit_tunnel.protocol = 4
            end
        else
            selcrit_tunnel.protocol = "*"
        end

        selcrit_tunnel.remote_addr = tun.ENDPOINT.."/32"
        selcrit_tunnel.local_port = "*"
        selcrit_tunnel.remote_port = "*"
        selcrit_tunnel = set_insert(selcrits, selcrit_tunnel)

        -- Selector for any traffic to us
        selcrit_to_us = fwall.selcrit_new()
        selcrit_to_us.local_addr = selcrit_to_us_lcl_nwk_address
        selcrit_to_us.remote_addr = "0.0.0.0/0"
        selcrit_to_us.local_port = "*"
        selcrit_to_us.remote_port = "*"
        selcrit_to_us.protocol = "*"
        selcrit_to_us = set_insert(selcrits, selcrit_to_us)

        -- Selector for DHCP traffic to us
        selcrit_dhcp_to_us = fwall.selcrit_new()
        selcrit_dhcp_to_us.local_addr = selcrit_lcl_itf_address
        selcrit_dhcp_to_us.remote_addr = "0.0.0.0/0"
        selcrit_dhcp_to_us.local_port = 68
        selcrit_dhcp_to_us.remote_port = 67
        selcrit_dhcp_to_us.protocol = 17
        selcrit_dhcp_to_us = set_insert(selcrits, selcrit_dhcp_to_us)
    end

    -- Firewall Policies
    -- ACCEPT
    pol_accept = fwall.policy_new()
    pol_accept.mode = "accept"
    pol_accept = set_insert(policies, pol_accept)

    -- DENY
    pol_deny = fwall.policy_new()
    pol_deny.mode = "deny"
    pol_deny = set_insert(policies, pol_deny)

    if ipsec_encrypt then
        -- ENCRYPT
        pol_ipsec = fwall.policy_new()
        -- IKE uses tunnel mode; non-IKE uses transport mode.
        if do_ike then
            pol_ipsec.mode = "tunnel"
            pol_ipsec.local_addr = "dynamic_inet"
        else
            pol_ipsec.mode = "transport"
            if is_set(tun.ENTRYPOINT) then
                pol_ipsec.local_addr = tun.ENTRYPOINT
            else
                pol_ipsec.local_addr = "dynamic_inet"
            end
        end
        if is_set(tun.IPSEC_ENDPOINT) then
            pol_ipsec.remote_addr = tun.IPSEC_ENDPOINT
        else
            pol_ipsec.remote_addr = tun.ENDPOINT
        end
        pol_ipsec.auth_alg = tun.IPSEC_AUTH_ALG
        pol_ipsec.esp_alg = tun.IPSEC_ENCRYPT_ALG
        if not do_ike and is_set(tun.NATT_INTERVAL) then
            pol_ipsec.remport = true
            pol_ipsec.proto = true
        end
        if is_set(tun.IPSEC_LIFE_SECS) then
            pol_ipsec.life_secs = tun.IPSEC_LIFE_SECS
        end
        if is_set(tun.IPSEC_LIFE_KBYTES) then
            pol_ipsec.life_kbytes = tun.IPSEC_LIFE_KBYTES
        end
        pol_ipsec = set_insert(policies, pol_ipsec)
    end

    -- Firewall Rules
    -- catchall rule; accept all
    rule_accept = fwall.flow_rule_new()
    rule_accept.inbound = true
    rule_accept.outbound = true
    rule_accept.selcrit = selcrit_all
    rule_accept.policy = pol_accept
    rule_accept = set_insert(rules, rule_accept)

    if ipsec_encrypt then
        -- drop all inbound traffic
        local rule_to_us = fwall.flow_rule_new()
        rule_to_us.inbound = true
        rule_to_us.outbound = false
        rule_to_us.selcrit = selcrit_to_us
        rule_to_us.policy = pol_deny
        rule_to_us = set_insert(rules, rule_to_us)

        -- pass through all DHCP traffic
        local rule_dhcp_to_us = fwall.flow_rule_new()
        rule_dhcp_to_us.inbound = true
        rule_dhcp_to_us.outbound = true
        rule_dhcp_to_us.selcrit = selcrit_dhcp_to_us
        rule_dhcp_to_us.policy = pol_accept
        rule_dhcp_to_us = set_insert(rules, rule_dhcp_to_us)

        -- encrypt all tunnel traffic
        local rule_tunnel = fwall.flow_rule_new()
        rule_tunnel.inbound = true
        rule_tunnel.outbound = true
        rule_tunnel.selcrit = selcrit_tunnel
        rule_tunnel.policy = pol_ipsec
        if ike_rule then
            rule_tunnel.ike_rule = ike_rule
        end
        rule_tunnel = set_insert(rules, rule_tunnel)
    end

    if do_ipsec then
        -- SAs
        out_sa = fwall.sa_new()
        out_sa.selcrit = selcrit_tunnel
        out_sa.policy = pol_ipsec
        out_sa.spi = tun.IPSEC_SPI_OUT
        out_sa.direction = "OUT"
        out_sa.auth_key = tun.IPSEC_AUTH_KEY_OUT
        out_sa.esp_key = tun.IPSEC_ESP_KEY_OUT
        out_sa = set_insert(sas, out_sa)

        in_sa = fwall.sa_new()
        in_sa.selcrit = selcrit_tunnel
        in_sa.policy = pol_ipsec
        in_sa.spi = tun.IPSEC_SPI_IN
        in_sa.direction = "IN"
        in_sa.auth_key = tun.IPSEC_AUTH_KEY_IN
        in_sa.esp_key = tun.IPSEC_ESP_KEY_IN
        in_sa = set_insert(sas, in_sa)
    end
end

function cfg_one_wan(WAN_ITF)
    -- ----------------------------------------------------------
    -- PPP
    -- ----------------------------------------------------------
    if WAN_ITF.ITF_TYPE == 'serial' then
        ppp0 = ppp.new(WAN_ITF.PORT)
        if is_set(WAN_ITF.PPP_LOCAL_IPV4) then
            ppp0.v4locaddr = WAN_ITF.PPP_LOCAL_IPV4
        end
        if is_set(WAN_ITF.PPP_REMOTE_IPV4) then
            ppp0.v4remaddr = WAN_ITF.PPP_REMOTE_IPV4
        end
        if is_set(WAN_ITF.PPP_CHAP_USER) and
               is_set(WAN_ITF.PPP_CHAP_PASSWD) then
            ppp0.chapuser = WAN_ITF.PPP_CHAP_USER
            ppp0.chappw = WAN_ITF.PPP_CHAP_PASSWD
        end
        if not LEGACY and is_set(WAN_ITF.PPP_ROUTE_IPV4) then
            ppp0.v4route = WAN_ITF.PPP_ROUTE_IPV4
        end

        ppp.enable(ppp0)
        -- Configurable WAN dialer Script Set Function
        if system.exists("wan_dialer.set_script") and
           is_set(WAN_ITF.WD_SCRIPT) then

            wan_dialer.set_script(WAN_ITF.WD_SCRIPT)
        end
    else
        -- add static address and default route if no DHCP
        if not is_true(WAN_ITF.DHCP) and is_set(WAN_ITF.ETH_LOCAL_IPV4) then
            sysif.config(eth0, WAN_ITF.ETH_LOCAL_IPV4)
            if is_set(WAN_ITF.ETH_DEFAULT_ROUTER) then
                route.add(eth0, "0.0.0.0/0", WAN_ITF.ETH_DEFAULT_ROUTER)
            end
        end
    end

    -- ----------------------------------------------------------
    -- Route Groups
    -- ----------------------------------------------------------
    -- Legacy firmware only supports a pinger.
    if LEGACY then
        if WAN_ITF.GROUPS and WAN_ITF.GROUPS[1] and
                is_set(WAN_ITF.GROUPS[1].PINGER_ADDR) then
            wan.pinger.addr = WAN_ITF.GROUPS[1].PINGER_ADDR
            wan.pinger.enable()
        end
    elseif WAN_ITF.GROUPS then
        for group_idx,GROUP in ipairs(WAN_ITF.GROUPS) do
            group = route.group_new()
            group.wan = WAN_ITF.obj
            group.ping_addr = GROUP.PINGER_ADDR
            if is_set(GROUP.PINGER_TEST_ITVL) then
                group.ping_test_interval = GROUP.PINGER_TEST_ITVL
            end
            if is_set(GROUP.PINGER_ITVL) then
                group.ping_interval = GROUP.PINGER_ITVL
            end
            if is_set(GROUP.PINGER_SIZE) then
                group.ping_size = GROUP.PINGER_SIZE
            end
            if is_set(GROUP.PINGER_COUNT) then
                group.ping_count = GROUP.PINGER_COUNT
            end
            if is_set(GROUP.PINGER_FAIL_COUNT) then
                group.ping_max_failure_count = GROUP.PINGER_FAIL_COUNT
            end
            if FWVER_GE_3_4_3 then
                group.ping_src_addr = GROUP.PINGER_SRC_ADDR
            end
            if FWVER_GE_3_6_0 then
                group.poison_delay_secs = GROUP.POISON_DELAY_SECS
                group.poison_tx_mode = GROUP.POISON_TX_MODE
            end
            if is_true(GROUP.BACKOFF) then
                group.backoff = true
            end
            if GROUP.ROUTES then
                routes = {}
                for j,ROUTE in ipairs(GROUP.ROUTES) do
                    -- Advertise group route destination to mesh.
                    srt_route = srt.route(rf0, ROUTE.ADDR)
                    if is_set(ROUTE.TAG) then
                        srt_route.tag = ROUTE.TAG
                    end
                    srt.advertise_route(srt_route)

                    -- Collect routes belonging to group.
                    routes[j] = route.key(ROUTE.ADDR, ROUTE.TAG)
                end
                group.routes = routes

            end
            route.group_enable(group)
        end
    end
end

--------------------------------
-- Only configure tunnels and IPsec for micro-APs in WAN- or dual-mode
-- (DA-10151 and DA-10152).
if is_set(wan.mode) and wan.mode ~= "mesh" then
    -- ----------------------------------------------------------
    -- RF IPv6 Subnet
    -- ----------------------------------------------------------
    if is_set(RF_V6_PREFIX) then
        srt.router_subnet = sysif.addr(rf0, RF_V6_PREFIX)
    end

    -- ----------------------------------------------------------
    -- RF IPv4 Addresses
    -- ----------------------------------------------------------
    if is_set(RF_V4_ADDRESSES) then
        for _,addr in ipairs(RF_V4_ADDRESSES) do
            sysif.config(rf0, addr)
        end
    end

    ---- Configure settings associated with WAN_ITF interfaces.
    if LEGACY then
        -- Legacy code only has one WAN_ITF; use the first.
        if WAN_ITFS and WAN_ITFS[1] then
            cfg_one_wan(WAN_ITFS[1])
        end
    else
        for _,WAN_ITF in ipairs(WAN_ITFS) do
            cfg_one_wan(WAN_ITF)
        end
    end

    ---- Configure tunnels.
    fwall.mode = "policy"
    for j,TUNNEL in ipairs(TUNNELS) do
        if is_set(TUNNEL.ENDPOINT) then
            if LEGACY then
                tun = tun64.add("tun"..(j - 1))
                tun.v6prefix = "::/0"
            else
                tun = tun64.add("tun"..(j - 1), TUNNEL.DST)
            end
            if is_set(TUNNEL.ENTRYPOINT) then
                tun.v4src = TUNNEL.ENTRYPOINT
            end
            if is_true(TUNNEL.GRE) then
                tun.gre = true
            end
            tun.v4dst = TUNNEL.ENDPOINT
            tun.v6src = TUNNEL.SRC
            tun64.enable(tun)

            -- Static local v4 address for IKE (both 6-in-4 and 4-in-4).
            if is_set(TUNNEL.ENTRYPOINT) then
                -- Unconfigure address first to ensure config operation succeeds.
                sysif.unconfig(rf0, TUNNEL.ENTRYPOINT)
                sysif.config(rf0, TUNNEL.ENTRYPOINT)
            end

            -- IPsec config,
            fwall_add_one(TUNNEL)
        end
    end

    -- Write the unique IPsec rules.
    for _,i in ipairs(ike_pols) do
        fwall.ike_policy_write(i)
    end
    for _,i in ipairs(ike_transes) do
        fwall.ike_transform_write(i)
    end
    for _,i in ipairs(ike_rules) do
        fwall.ike_rule_write(i)
    end
    for _,i in ipairs(selcrits) do
        fwall.selcrit_write(i)
    end
    for _,i in ipairs(policies) do
        fwall.policy_write(i)
    end
    for _,i in ipairs(rules) do
        fwall.flow_rule_write(i)
    end
    for _,i in ipairs(sas) do
        fwall.sa_write(i)
    end

    if is_set(NTP_SERVER) and is_set(NTP_MODE) then
        ntp.server_address = NTP_SERVER
        ntp.mode = NTP_MODE
    end

    if is_set(MLME_LG_CFG) then
        mlme.lg_cfg = MLME_LG_CFG
    end

    if is_set(ZERO_X_MUST_LAST_GASP_LEN) and FWVER_GE_3_8_1 then
        zero_x.must_last_gasp_len = ZERO_X_MUST_LAST_GASP_LEN
    end

    if is_set(TRECK_ROUTES) then
        for _,ROUTE in ipairs(TRECK_ROUTES) do
            route.add(ROUTE.INTERFACE, ROUTE.DST, ROUTE.NEXTHOP)
        end
    end
end

if is_set(DNS_SERVER) and is_set(DNS_ZONE) then
    dns.server_add(dns.server_new(DNS_SERVER, DNS_ZONE))
end

if is_set(TRAP_HOST) then
    trap.server_addr = TRAP_HOST
end

if FWVER_GE_4_6_0 and is_set(SECURE_TRAP_PORT) then
    trap.secure_port = SECURE_TRAP_PORT
end

if FWVER_GE_4_6_0 and is_set(SECURE_TRAP_PUB_KEY) then
    trap.server_public_key = SECURE_TRAP_PUB_KEY
end
-- ----------------------------------------------------------
-- Link Layer Security
-- ----------------------------------------------------------
if is_set(LINK_LAYER_SECURITY) then
    mlme.security_level = LINK_LAYER_SECURITY
end
if is_set(NDXP_SERVER_ADDR) and FWVER_GE_3_8_1 then
    ndxp.server_addr = NDXP_SERVER_ADDR
end
if is_set(NM_SEC_NDXP_SERVER) and FWVER_GE_3_8_1 then
   ndxp.server_addr = NM_SEC_NDXP_SERVER
end
-- ----------------------------------------------------------
-- AMI Pushback and cost bump settings
-- ----------------------------------------------------------
if is_set(AMI_PUSHBACK_COST_BUMP) then
    srt.ami_pushback_cost_bump = AMI_PUSHBACK_COST_BUMP
end
if is_set(AMI_PUSHBACK_LOWER_TIME) then
    srt.ami_pushback_lower_time = AMI_PUSHBACK_LOWER_TIME
end
if is_set(AMI_PUSHBACK_UTIL_PERIOD) then
    srt.ami_pushback_util_period = AMI_PUSHBACK_UTIL_PERIOD
end
if is_set(AMI_PUSHBACK_UTIL_THRESH) then
    srt.ami_pushback_util_thresh = AMI_PUSHBACK_UTIL_THRESH
end

-- Mutt configuration
if is_set(ANTENNA_INT_2_4_HAN_GAIN) then
    antenna.int_2_4_han_gain = ANTENNA_INT_2_4_HAN_GAIN
end
if is_set(ANTENNA_INT_900_FHSS_GAIN) then
    antenna.int_900_fhss_gain = ANTENNA_INT_900_FHSS_GAIN
end
if is_set(ANTENNA_EXT_2_4_HAN_GAIN) then
    antenna.ext_2_4_han_gain = ANTENNA_EXT_2_4_HAN_GAIN
end
if is_set(ANTENNA_EXT_900_FHSS_GAIN) then
    antenna.ext_900_fhss_gain = ANTENNA_EXT_900_FHSS_GAIN
end
if is_set(ZERO_X_IGNORE_PF_AFTER_TX) then
    zero_x.ignore_pf_after_tx = ZERO_X_IGNORE_PF_AFTER_TX
end
if is_set(ANTENNA_EXT_MASK) then
    antenna.ext_mask = ANTENNA_EXT_MASK
end
if is_set(PHY_PHY_PWR_OUT_900) then
    phy.pwr_out_900 = PHY_PHY_PWR_OUT_900
end
if is_set(CONF_MLME_IGNORE_DA_CFG) and FWVER_GE_3_6_0 then
    conf.set(1116, CONF_MLME_IGNORE_DA_CFG)
end
if is_set(CONF_SRT_NACK_FIRST_LVL) then
    conf.set(232, CONF_SRT_NACK_FIRST_LVL)
end
if is_set(CONF_SRT_NACK_SECOND_LVL) then
    srt.nack_second_lvl = CONF_SRT_NACK_SECOND_LVL
end
if is_set(CONF_SRT_NACK_THIRD_LVL) then
    srt.nack_third_lvl = CONF_SRT_NACK_THIRD_LVL
end
if is_set(MMESH_MAC_ENABLE) then
    conf.set(1193, MMESH_MAC_ENABLE)
end
