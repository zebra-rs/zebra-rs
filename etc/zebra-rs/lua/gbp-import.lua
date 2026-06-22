-- gbp-import.lua — zebra-rs port of the FRR "route receive" GBP script
-- (ENOG90 "FRR Scripting は何ができるのか", slides 27–30), plus the withdraw
-- teardown the talk wished for but FRR could not do (slide 32, #1).
--
-- On receiving an EVPN Type-2 (MAC) route, recover the group tag from its
-- GPI extended community and add the MAC to the matching nftables set; on
-- withdrawal, remove it.
--
-- Bind:
--   router bgp 65000 {
--     lua-script gbp { source-path /etc/zebra-rs/lua/gbp-import.lua; }
--     loc-rib-hook l2vpn-evpn { import gbp; withdraw gbp; }
--   }
--
-- FRR → zebra-rs port notes:
--   * `route_match` → `loc_rib_import` (the receive / Adj-RIB-In→Loc-RIB hook).
--   * Regex on `tostring(prefix.network)` → structured `prefix.evpn.mac`.
--   * The `ec:byte(1)/ec:byte(2)` loop + `string.unpack(">BBHHH", ec)` →
--     `ecom.parse_gpi(ec)` (returns the tag, or nil if `ec` is not a GPI
--     community). The raw byte/unpack form also works in zebra-rs.
--   * Blocking, unsandboxed `os.execute("nft ...")` → non-blocking
--     `sideeffect.nft{...}`, which enqueues onto a background drainer.
--     (`os` is intentionally absent from the sandbox.)

local GBP_TABLE = "bridge gbp_filter"

-- Receive: program the nftables set from the GPI tag.
function loc_rib_import(prefix, attributes, peer,
                        RM_FAILURE, RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE)
    local mac = prefix.evpn and prefix.evpn.mac
    if mac then
        for _, ec in ipairs(attributes.ext_community) do
            local tag = ecom.parse_gpi(ec)
            if tag then
                sideeffect.nft{ op = "add", table = GBP_TABLE,
                                set = "tag_" .. tag, elem = mac }
                break
            end
        end
    end
    return { action = RM_NOMATCH }
end

-- Withdraw: the route is leaving the Loc-RIB. `attributes` are the STORED
-- attributes of the withdrawn path (read-only), so the tag is still
-- recoverable — remove the nftables element. FRR has no hook here: its
-- route-map is not run on withdrawal, and the zebra dataplane hook lacks
-- the BGP ext-communities. zebra-rs is one process, so it just works.
function loc_rib_withdraw(prefix, attributes, peer,
                          RM_FAILURE, RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE)
    local mac = prefix.evpn and prefix.evpn.mac
    if mac then
        for _, ec in ipairs(attributes.ext_community) do
            local tag = ecom.parse_gpi(ec)
            if tag then
                sideeffect.nft{ op = "delete", table = GBP_TABLE,
                                set = "tag_" .. tag, elem = mac }
                break
            end
        end
    end
    return { action = RM_NOMATCH }
end
