use nom::{error::ParseError, IResult};

// many0 which avoid passing empty input to the parser.
pub fn many0<'a, O, E: ParseError<&'a [u8]>>(
    parser: impl Fn(&'a [u8]) -> IResult<&'a [u8], O, E>,
) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Vec<O>, E> {
    move |input| {
        let mut res = Vec::new();
        let mut remaining = input;

        while !remaining.is_empty() {
            let (new_input, value) = parser(remaining)?;
            remaining = new_input;
            res.push(value);
        }

        Ok((remaining, res))
    }
}
