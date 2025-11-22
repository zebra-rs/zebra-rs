use isis_packet::*;

#[test]
fn test_isis_parse_error_display() {
    let err = IsisParseError::tlv_parse_error(IsisTlvType::AreaAddr, "invalid area address");
    assert_eq!(
        err.to_string(),
        "TLV parse error: AreaAddr - invalid area address"
    );

    let err = IsisParseError::pdu_parse_error(IsisType::L1Hello, "invalid hello PDU");
    assert_eq!(
        err.to_string(),
        "PDU parse error: L1Hello - invalid hello PDU"
    );

    let err = IsisParseError::InvalidDiscriminator { found: 0x84 };
    assert_eq!(
        err.to_string(),
        "Invalid IS-IS discriminator: expected 0x83, found 0x84"
    );

    let err = IsisParseError::InvalidPduType { pdu_type: 0xFF };
    assert_eq!(err.to_string(), "Invalid PDU type: 0xff");

    let err = IsisParseError::UnknownTlvType { tlv_type: 0x99 };
    assert_eq!(err.to_string(), "Unknown TLV type: 0x99");
}

#[test]
fn test_isis_parse_error_debug() {
    let err = IsisParseError::InvalidPacketLength {
        expected: 100,
        found: 50,
    };
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("InvalidPacketLength"));
    assert!(debug_str.contains("expected: 100"));
    assert!(debug_str.contains("found: 50"));
}

#[test]
fn test_isis_parse_error_equality() {
    let err1 = IsisParseError::tlv_parse_error(IsisTlvType::AreaAddr, "test");
    let err2 = IsisParseError::tlv_parse_error(IsisTlvType::AreaAddr, "test");
    let err3 = IsisParseError::tlv_parse_error(IsisTlvType::IsNeighbor, "test");

    assert_eq!(err1, err2);
    assert_ne!(err1, err3);
}

#[test]
fn test_isis_parse_error_clone() {
    let err = IsisParseError::InvalidIpAddress {
        message: "test".to_string(),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_isis_parse_error_variants() {
    let errors = vec![
        IsisParseError::InvalidPacketLength {
            expected: 100,
            found: 50,
        },
        IsisParseError::InvalidTlvLength {
            tlv_type: IsisTlvType::AreaAddr,
            expected: 10,
            found: 5,
        },
        IsisParseError::InvalidDiscriminator { found: 0x84 },
        IsisParseError::InvalidPduType { pdu_type: 0xFF },
        IsisParseError::UnknownTlvType { tlv_type: 0x99 },
        IsisParseError::InvalidChecksum {
            expected: 0x1234,
            found: 0x5678,
        },
        IsisParseError::IncompleteData { needed: 42 },
        IsisParseError::InvalidIpAddress {
            message: "test".to_string(),
        },
        IsisParseError::InvalidNsapAddress {
            message: "test".to_string(),
        },
        IsisParseError::InvalidSubTlv {
            message: "test".to_string(),
        },
        IsisParseError::InvalidSidLabel {
            message: "test".to_string(),
        },
        IsisParseError::InvalidPrefixLength { length: 33 },
        IsisParseError::InvalidNeighborId {
            message: "test".to_string(),
        },
        IsisParseError::InvalidLspId {
            message: "test".to_string(),
        },
        IsisParseError::BufferOverflow {
            attempted: 100,
            available: 50,
        },
    ];

    for err in errors {
        // Test that each error can be displayed
        let _ = err.to_string();

        // Test that each error can be formatted with Debug
        let _ = format!("{:?}", err);

        // Test that each error is cloneable
        let _ = err.clone();
    }
}

#[test]
fn test_isis_parse_error_helper_functions() {
    let err = IsisParseError::incomplete_data(42);
    assert!(matches!(err, IsisParseError::IncompleteData { needed: 42 }));

    let err = IsisParseError::nom_error("test message");
    assert!(matches!(err, IsisParseError::NomError { .. }));

    let err = IsisParseError::invalid_checksum(0x1234, 0x5678);
    assert!(matches!(
        err,
        IsisParseError::InvalidChecksum {
            expected: 0x1234,
            found: 0x5678
        }
    ));

    let err = IsisParseError::buffer_overflow(100, 50);
    assert!(matches!(
        err,
        IsisParseError::BufferOverflow {
            attempted: 100,
            available: 50
        }
    ));
}

#[test]
fn test_isis_parse_result_type() {
    let success: IsisParseResult<u32> = Ok(42);
    let failure: IsisParseResult<u32> = Err(IsisParseError::incomplete_data(10));

    assert!(success.is_ok());
    assert!(failure.is_err());
    assert!(matches!(
        IsisParseError::incomplete_data(10),
        IsisParseError::IncompleteData { needed: 10 }
    ));
}
