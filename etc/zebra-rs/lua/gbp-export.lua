-- gbp-export.lua — zebra-rs port of the FRR "route advertise" GBP script
-- (ENOG90 "FRR Scripting は何ができるのか", slides 21–25).
--
-- On EVPN Type-2 (MAC) advertisement, look the MAC up in a MAC→tag map and
-- stamp the route with a Group-Policy-ID (GPI) extended community, so the
-- receiver can enforce group-based policy.
--
-- Bind:
--   router bgp 65000 {
--     lua-script gbp { source-path /etc/zebra-rs/lua/gbp-export.lua; }
--     lua-map sgt    { source-path /etc/zebra-rs/lua/sgt.json; }   // {"aa:bb:..":"100"}
--     adj-rib-out-hook l2vpn-evpn { export gbp; }
--   }
--
-- FRR → zebra-rs port notes:
--   * `route_match` → `adj_rib_out` (the advertise / Adj-RIB-Out hook).
--   * Regex on `tostring(prefix.network)` → structured `prefix.evpn.mac`.
--   * Blocking `http.request(...)` + `json.decode(...)` → non-blocking
--     `map.get("sgt", mac)` (a config-seeded lookup table).
--   * `string.pack(">BBHHH", 0x03, 0x17, 0, 0, tag)` → `ecom.gpi(tag)`.
--     (The raw `string.pack` form also works — ext_community entries are
--     8-byte values — `ecom.gpi` is just the tidy spelling.)

function adj_rib_out(prefix, attributes, peer,
                     RM_FAILURE, RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE)
    local mac = prefix.evpn and prefix.evpn.mac
    if not mac then
        return { action = RM_NOMATCH }
    end

    local tag = map.get("sgt", mac)
    if not tag then
        return { action = RM_NOMATCH }
    end

    table.insert(attributes.ext_community, ecom.gpi(tonumber(tag)))
    return { action = RM_MATCH_AND_CHANGE, attributes = attributes }
end
