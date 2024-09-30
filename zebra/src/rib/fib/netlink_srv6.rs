use netlink_packet_route::route::{RouteAttribute, RouteLwEnCapType, RouteMessage};

// int rta_addattr_l(struct rtattr *rta, int maxlen, int type,
//     const void *data, int alen)
// {
//     struct rtattr *subrta;
//     int len = RTA_LENGTH(alen);

//     if (RTA_ALIGN(rta->rta_len) + RTA_ALIGN(len) > maxlen) {
// 	fprintf(stderr,
// 	    "rta_addattr_l: Error! max allowed bound %d exceeded\n",
// 	    maxlen);
// 	return -1;
//     }
//     subrta = (struct rtattr *)(((char *)rta) + RTA_ALIGN(rta->rta_len));
//     subrta->rta_type = type;
//     subrta->rta_len = len;
//     if (alen)
// 		memcpy(RTA_DATA(subrta), data, alen);
// 	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + RTA_ALIGN(len);
//     return 0;
// }

pub struct RouteLwRequest {
    message: RouteMessage,
}

// impl RouteLwRequest {
//     fn a() {}
// }

pub fn srv6_encap(handle: &rtnetlink::Handle) {
    let route = handle.route();

    let encap_type = RouteAttribute::EncapType(RouteLwEnCapType::Seg6);
    let encap = RouteAttribute::Encap(Vec::new());

    println!("srv6_encap {}", RouteLwEnCapType::Seg6);
}
