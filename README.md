# bgpd

Here is work in progress code for upcoming new zebra's bgpd.

## BGP attributes

Supported BGP attributes.

| Value | Name             | Reference                                              |
|-------|------------------|--------------------------------------------------------|
| 1     | ORIGIN           | [RFC4271](https://www.rfc-editor.org/rfc/rfc4271.html) |
| 2     | AS_PATH          | [RFC4271](https://www.rfc-editor.org/rfc/rfc4271.html) |
| 3     | NEXT_HOP         | [RFC4271](https://www.rfc-editor.org/rfc/rfc4271.html) |
| 4     | MULTI_EXIT_DISC  | [RFC4271](https://www.rfc-editor.org/rfc/rfc4271.html) |
| 5     | LOCAL_PREF       | [RFC4271](https://www.rfc-editor.org/rfc/rfc4271.html) |
| 6     | ATOMIC_AGGREGATE | [RFC4271](https://www.rfc-editor.org/rfc/rfc4271.html) |
| 7     | AGGREGATOR       | [RFC4271](https://www.rfc-editor.org/rfc/rfc4271.html) |
| 8     | COMMUNITIES      | [RFC1997](https://www.rfc-editor.org/rfc/rfc1997.html) |
| 14    | MP_REACH_NLRI    | [RFC4760](https://www.rfc-editor.org/rfc/rfc4760.html) |
| 15    | MP_UNREACH_NLRI  | [RFC4760](https://www.rfc-editor.org/rfc/rfc4760.html) |

## BGP capability

Supported BGP capability.

| Value | Name                                     | Reference                                              |
|-------|------------------------------------------|--------------------------------------------------------|
| 1     | Multiprotocol Extensions for BGP-4       | [RFC2858](https://www.rfc-editor.org/rfc/rfc2858.html) |
| 2     | Route Refresh Capability for BGP-4       | [RFC2918](https://www.rfc-editor.org/rfc/rfc2918.html) |
| 64    | Graceful Restart Capability              | [RFC4724](https://www.rfc-editor.org/rfc/rfc4724.html) |
| 65    | Support for 4-octet AS number capability | [RFC6793](https://www.rfc-editor.org/rfc/rfc6793.html) |
| 128   | Prestandard Route Refresh (deprecated)   | [RFC8810](https://www.rfc-editor.org/rfc/rfc8810.html) |

## Configuration

Simplified version of gNMI path can be used to configure BGP. You can change the
begninning of `main()`` function.

``` shell
"/bgp/global/as/1"
"/bgp/global/router-id/10.211.65.2"
"/bgp/neighbors/address/10.211.55.65/peer-as/100"
```

We will migrate to forthcoming rust based openconfigd in near future.
