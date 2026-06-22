-- metric.lua — zebra-rs port of the basic FRR Scripting example
-- (ENOG90 "FRR Scripting は何ができるのか", slide 7).
--
-- FRR original (route-map `match script`):
--   function route_match(prefix, attributes, peer, ...)
--     if prefix.network == "172.16.10.4/24" then
--       return { action = RM_NOMATCH }
--     else
--       attributes["metric"] = attributes["metric"] + 7
--       return { action = RM_MATCH_AND_CHANGE, attributes = attributes }
--     end
--   end
--
-- Port notes:
--   * `route_match` → a named hook. Bind this file's `loc_rib_import` to
--       router bgp { loc-rib-hook ipv4-unicast { import metric } }
--     (rename the function to `adj_rib_out` to run it on advertise instead).
--   * FRR's `attributes["metric"]` is the MED; in zebra-rs it is
--     `attributes.med`. Guarded with `or 0` since MED may be unset.

function loc_rib_import(prefix, attributes, peer,
                        RM_FAILURE, RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE)
    if prefix.network == "172.16.10.4/24" then
        return { action = RM_NOMATCH }
    end
    attributes.med = (attributes.med or 0) + 7
    return { action = RM_MATCH_AND_CHANGE, attributes = attributes }
end
