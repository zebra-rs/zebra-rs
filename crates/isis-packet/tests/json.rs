use isis_packet::*;

#[test]
pub fn json_test() {
    let prefix = prefix::IsisSubPrefixSid {
        flags: 0.into(),
        algo: 0.into(),
        sid: SidLabelValue::Index(100),
    };
    let tlv = prefix::IsisSubTlv::PrefixSid(prefix);
    let serialized = serde_json::to_string(&tlv).unwrap();
    println!("{}", serialized);
}

#[test]
pub fn json_round_trip_test() {
    // Test round-trip serialization/deserialization for various types

    // Test IsisType
    let isis_type = IsisType::L2Hello;
    let serialized = serde_json::to_string(&isis_type).unwrap();
    let deserialized: IsisType = serde_json::from_str(&serialized).unwrap();
    assert_eq!(isis_type, deserialized);

    // Test IsisTlvType
    let tlv_type = IsisTlvType::RouterCap;
    let serialized = serde_json::to_string(&tlv_type).unwrap();
    let deserialized: IsisTlvType = serde_json::from_str(&serialized).unwrap();
    assert_eq!(tlv_type, deserialized);

    // Test Algo
    let algo = Algo::FlexAlgo(200);
    let serialized = serde_json::to_string(&algo).unwrap();
    let deserialized: Algo = serde_json::from_str(&serialized).unwrap();
    assert_eq!(algo, deserialized);

    // Test SidLabelValue
    let sid_value = SidLabelValue::Index(100);
    let serialized = serde_json::to_string(&sid_value).unwrap();
    let deserialized: SidLabelValue = serde_json::from_str(&serialized).unwrap();
    assert_eq!(sid_value, deserialized);

    let sid_value = SidLabelValue::Label(2000);
    let serialized = serde_json::to_string(&sid_value).unwrap();
    let deserialized: SidLabelValue = serde_json::from_str(&serialized).unwrap();
    assert_eq!(sid_value, deserialized);

    // Test IsLevel
    let level = IsLevel::L1L2;
    let serialized = serde_json::to_string(&level).unwrap();
    let deserialized: IsLevel = serde_json::from_str(&serialized).unwrap();
    assert_eq!(level, deserialized);

    // Test prefix::IsisSubPrefixSid
    let prefix_sid = prefix::IsisSubPrefixSid {
        flags: 0.into(),
        algo: Algo::Spf,
        sid: SidLabelValue::Index(100),
    };
    let serialized = serde_json::to_string(&prefix_sid).unwrap();
    let deserialized: prefix::IsisSubPrefixSid = serde_json::from_str(&serialized).unwrap();
    assert_eq!(prefix_sid, deserialized);

    // Test prefix::IsisSubTlv
    let prefix_tlv = prefix::IsisSubTlv::PrefixSid(prefix_sid);
    let serialized = serde_json::to_string(&prefix_tlv).unwrap();
    let deserialized: prefix::IsisSubTlv = serde_json::from_str(&serialized).unwrap();
    assert_eq!(prefix_tlv, deserialized);

    // Test Behavior
    let behavior = srv6::Behavior::EndX;
    let serialized = serde_json::to_string(&behavior).unwrap();
    let deserialized: srv6::Behavior = serde_json::from_str(&serialized).unwrap();
    assert_eq!(behavior, deserialized);

    let behavior = srv6::Behavior::Resv(1234);
    let serialized = serde_json::to_string(&behavior).unwrap();
    let deserialized: srv6::Behavior = serde_json::from_str(&serialized).unwrap();
    assert_eq!(behavior, deserialized);

    // Test cap::SidLabelTlv
    let sid_label = cap::SidLabelTlv::Label(16001);
    let serialized = serde_json::to_string(&sid_label).unwrap();
    let deserialized: cap::SidLabelTlv = serde_json::from_str(&serialized).unwrap();
    assert_eq!(sid_label, deserialized);

    let sid_label = cap::SidLabelTlv::Index(1000);
    let serialized = serde_json::to_string(&sid_label).unwrap();
    let deserialized: cap::SidLabelTlv = serde_json::from_str(&serialized).unwrap();
    assert_eq!(sid_label, deserialized);

    // Test complex structure: IsisTlvAreaAddr
    let area_addr = IsisTlvAreaAddr {
        area_addr: vec![0x49, 0x00, 0x01],
    };
    let serialized = serde_json::to_string(&area_addr).unwrap();
    let deserialized: IsisTlvAreaAddr = serde_json::from_str(&serialized).unwrap();
    assert_eq!(area_addr, deserialized);

    // Test IsisSysId
    let sys_id = IsisSysId {
        id: [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
    };
    let serialized = serde_json::to_string(&sys_id).unwrap();
    let deserialized: IsisSysId = serde_json::from_str(&serialized).unwrap();
    assert_eq!(sys_id, deserialized);

    println!("All round-trip JSON serialization/deserialization tests passed!");
}
