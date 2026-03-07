use nom::combinator::complete;
use nom::error::ParseError;
use nom::multi::many0;
use nom::{Input, Parser};

/// Applies the parser zero or more times, treating incomplete input as end-of-input.
///
/// This is equivalent to `many0(complete(parser))`. It wraps the inner parser
/// with `complete()` to convert `Incomplete` errors into regular errors,
/// which `many0` interprets as "stop and return accumulated results."
pub fn many0_complete<I, O, E, F>(parser: F) -> impl Parser<I, Output = Vec<O>, Error = E>
where
    I: Clone + Input,
    E: ParseError<I>,
    F: Parser<I, Output = O, Error = E>,
{
    many0(complete(parser))
}
