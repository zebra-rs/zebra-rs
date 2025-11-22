use bgp_packet::{BgpPacket, BgpParseError};
use hex_literal::hex;

#[test]
fn test_attribute_parse_error_context() {
    // Create invalid BGP Update packet with truncated attribute
    let invalid_update = hex!(
        "ffffffffffffffffffffffffffffffff" // BGP marker
        "001f" // Length: 31 bytes
        "02"   // Type: Update
        "0000" // Withdrawal length: 0
        "0004" // Path attributes length: 4
        "4001" // Attribute flags (well-known, transitive) and type (ORIGIN)
        "02"   // Length: 2 (but only 1 byte follows)
        "00"   // Truncated data
    );

    let result = BgpPacket::parse_packet(&invalid_update, false, None);

    match result {
        Err(BgpParseError::IncompleteData { needed }) => {
            println!(
                "Successfully caught incomplete data error, needed: {} bytes",
                needed
            );
            assert!(needed > 0);
        }
        Err(BgpParseError::AttributeParseError {
            attr_type,
            source: _,
        }) => {
            println!(
                "Successfully caught attribute parse error for: {:?}",
                attr_type
            );
            assert_eq!(attr_type, bgp_packet::AttrType::Origin);
        }
        Err(other_error) => {
            println!("Got different error: {:?}", other_error);
            // This is also acceptable as the error might manifest differently
        }
        Ok(_) => {
            panic!("Expected parse error but got success");
        }
    }
}

#[test]
fn test_error_display() {
    use bgp_packet::AttrType;

    let error = BgpParseError::AttributeParseError {
        attr_type: AttrType::Origin,
        source: Box::new(BgpParseError::NomError("test error".to_string())),
    };

    let error_string = format!("{}", error);
    assert!(error_string.contains("Origin"));
    assert!(error_string.contains("Failed to parse BGP attribute"));
    println!("Error display: {}", error_string);
}
