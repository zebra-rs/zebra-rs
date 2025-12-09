use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, Token, parse_macro_input};

/// Attribute macro to define OSPF packet handler context.
///
/// This macro automatically injects constants for packet type and direction
/// at the beginning of the function, which can then be used with `ospf_pkt_trace!`.
///
/// # Usage
///
/// ```ignore
/// #[ospf_packet_handler(Hello, Recv)]
/// pub fn ospf_hello_recv(oi: &mut OspfLink, packet: &Ospfv2Packet, src: &Ipv4Addr) {
///     // _OSPF_PKT_TYPE and _OSPF_PKT_DIR are now available
///     ospf_pkt_trace!(oi.tracing, "[Hello] recv from {}", src);
/// }
/// ```
#[proc_macro_attribute]
pub fn ospf_packet_handler(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr with parse_handler_args);
    let mut input_fn = parse_macro_input!(item as ItemFn);

    let (packet_type, direction) = args;

    // Create the constant definitions to inject at the start of the function
    let inject_code = quote! {
        const _OSPF_PKT_TYPE: crate::ospf::tracing::PacketType =
            crate::ospf::tracing::PacketType::#packet_type;
        const _OSPF_PKT_DIR: crate::ospf::tracing::PacketDirection =
            crate::ospf::tracing::PacketDirection::#direction;
    };

    // Get the original function body
    let original_body = &input_fn.block;

    // Create new body with injected constants
    let new_body: syn::Block = syn::parse_quote! {
        {
            #inject_code
            #original_body
        }
    };

    // Replace the function body - need to wrap in Box
    input_fn.block = Box::new(new_body);

    TokenStream::from(quote! {
        #input_fn
    })
}

/// Parse the handler arguments: (PacketType, Direction)
fn parse_handler_args(input: syn::parse::ParseStream) -> syn::Result<(syn::Ident, syn::Ident)> {
    let packet_type: syn::Ident = input.parse()?;
    input.parse::<Token![,]>()?;
    let direction: syn::Ident = input.parse()?;

    // Validate packet type
    let valid_packet_types = ["Hello", "DbDesc", "LsRequest", "LsUpdate", "LsAck"];
    if !valid_packet_types.contains(&packet_type.to_string().as_str()) {
        return Err(syn::Error::new(
            packet_type.span(),
            format!(
                "Invalid packet type '{}'. Expected one of: {:?}",
                packet_type, valid_packet_types
            ),
        ));
    }

    // Validate direction
    let valid_directions = ["Send", "Recv", "Both"];
    if !valid_directions.contains(&direction.to_string().as_str()) {
        return Err(syn::Error::new(
            direction.span(),
            format!(
                "Invalid direction '{}'. Expected one of: {:?}",
                direction, valid_directions
            ),
        ));
    }

    Ok((packet_type, direction))
}
