-- gbp-example.lua — example zebra-rs Lua policy script (GBP over EVPN).
--
-- zebra-rs ships the embedded Lua engine by default. A script is bound to
-- a hook from BGP config, e.g.:
--
--   router bgp 65000 {
--     lua-script GBP { source-path /usr/share/zebra-rs/lua/gbp-example.lua; }
--     lua-map sgt   { source-path /usr/share/zebra-rs/lua/sgt.json; }   -- MAC -> tag
--     loc-rib-hook l2vpn-evpn {
--       import GBP;     -- on receive: program nftables from the GPI tag
--       withdraw GBP;   -- on withdraw: tear the nftables element down
--     }
--     adj-rib-out-hook l2vpn-evpn { export GBP; }  -- on advertise: add the GPI tag
--   }
--
-- A hook function receives (prefix, attributes, peer, RM_FAILURE,
-- RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE) and returns
--   { action = RM_NOMATCH }                        -- admit unchanged
--   { action = RM_FAILURE }                        -- deny / suppress
--   { action = RM_MATCH_AND_CHANGE, attributes = attributes }  -- rewrite attrs
-- The withdraw hook is observe-only: its tables are read-only and its
-- return value is ignored.
--
-- Available to scripts: string/table/math, and the host helpers
--   ecom.gpi(tag) / ecom.parse_gpi(value)   -- GPI ext-community (0x03/0x17)
--   map.get(namespace, key)                 -- config-seeded lookup table
--   zlog.info/warn/error(msg)               -- daemon log
--   sideeffect.nft{ op=, table=, set=, elem= }  -- non-blocking nftables op
-- (os/io/network access is intentionally absent — the engine is sandboxed.)

local GBP_TABLE = "bridge gbp_filter"

-- Advertise side: stamp the EVPN Type-2 (MAC) route with the GPI
-- Extended Community for the endpoint's group, looked up MAC -> tag.
function adj_rib_out(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
    local mac = prefix.evpn and prefix.evpn.mac
    if mac then
        local tag = map.get("sgt", mac)
        if tag then
            table.insert(attributes.ext_community, ecom.gpi(tonumber(tag)))
            return { action = CHANGE, attributes = attributes }
        end
    end
    return { action = NOMATCH }
end

-- Receive side: recover the group tag from the GPI ext-community and add
-- the MAC to the matching nftables set.
function loc_rib_import(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
    local mac = prefix.evpn and prefix.evpn.mac
    if mac then
        for _, ec in ipairs(attributes.ext_community) do
            local tag = ecom.parse_gpi(ec)
            if tag then
                sideeffect.nft{ op = "add", table = GBP_TABLE,
                                set = "tag_" .. tag, elem = mac }
                zlog.info("gbp: " .. mac .. " -> tag " .. tag)
                break
            end
        end
    end
    return { action = NOMATCH }
end

-- Teardown: the path is leaving the Loc-RIB. `attributes` are the STORED
-- attributes of the withdrawn route (read-only), so the tag is still
-- recoverable — remove the nftables element. (FRR cannot do this.)
function loc_rib_withdraw(prefix, attributes, peer, FAIL, NOMATCH, MATCH, CHANGE)
    local mac = prefix.evpn and prefix.evpn.mac
    if mac then
        for _, ec in ipairs(attributes.ext_community) do
            local tag = ecom.parse_gpi(ec)
            if tag then
                sideeffect.nft{ op = "delete", table = GBP_TABLE,
                                set = "tag_" .. tag, elem = mac }
                zlog.info("gbp: withdraw " .. mac .. " from tag " .. tag)
                break
            end
        end
    end
    return { action = NOMATCH }
end
