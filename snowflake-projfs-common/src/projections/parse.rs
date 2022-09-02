use crate::projections::{FileAccess, ProjectionEntry};
use nom::branch::alt;
use nom::bytes::complete::{tag, take_until, take_until1};
use nom::character::complete::multispace0;
use nom::combinator::{map, peek};
use nom::error::ParseError;
use nom::multi::separated_list0;
use nom::sequence::delimited;
use nom::{IResult, Parser};
use os_str_bytes::RawOsString;

pub fn parse_projection(s: &[u8]) -> Option<Vec<ProjectionEntry>> {
    parse_full_projection(s)
        .ok()
        .map(|(i, projections)| projections)
}

#[cfg(test)]
mod tests {
    use crate::projections::parse::{parse_directory, parse_file, parse_portal, parse_projection};
    use crate::projections::{FileAccess, ProjectionEntry};
    use std::ffi::{OsStr, OsString};
    use std::path::PathBuf;
    use std::str::FromStr;

    #[test]
    fn parse_projection_string() {
        let projection = br#"
f(/hello.world|C:\test.txt|r);
d(/directory|);
d(/dir2|);
p(/portal|C:\test|rw|protected:file:|);
f(/dir2/d0|C:\test.txt|r);
        "#;

        let parsed = parse_projection(projection).unwrap();
        assert_eq!(
            parsed,
            vec![
                ProjectionEntry::File {
                    name: OsString::from_str("/hello.world").unwrap().into(),
                    source: PathBuf::from_str("C:\\test.txt").unwrap(),
                    access: FileAccess::Read
                },
                ProjectionEntry::Directory {
                    name: OsStr::new("/directory").into(),
                },
                ProjectionEntry::Portal {
                    name: OsString::from_str("/portal").unwrap().into(),
                    source: PathBuf::from_str("C:\\test").unwrap(),
                    access: FileAccess::ReadWrite,
                    protect: vec![PathBuf::from("protected"), PathBuf::from("file"),]
                }
            ]
        );
    }

    #[test]
    fn parse_file_test() {
        let projection = br#"f(/hello.world|C:\test.txt|r)"#;

        let (_, parsed) = parse_file(projection).unwrap();
        assert_eq!(
            parsed,
            ProjectionEntry::File {
                name: OsString::from_str("/hello.world").unwrap().into(),
                source: PathBuf::from_str("C:\\test.txt").unwrap(),
                access: FileAccess::Read
            }
        );
    }

    #[test]
    fn parse_portal_test() {
        let projection = br#"p(/portal|C:\test|rw|protected:file:|);"#;
        let (_, parsed) = parse_portal(projection).unwrap();
        assert_eq!(
            parsed,
            ProjectionEntry::Portal {
                name: OsString::from_str("/portal").unwrap().into(),
                source: PathBuf::from_str("C:\\test").unwrap(),
                access: FileAccess::ReadWrite,
                protect: vec![PathBuf::from("protected"), PathBuf::from("file"),]
            }
        );
    }
    #[test]
    fn parse_directory_test() {
        let projection = br#"d(/directory|);"#;
        let (_, parsed) = parse_directory(projection).unwrap();
        assert_eq!(
            parsed,
            ProjectionEntry::Directory {
                name: OsStr::new("/directory").into(),
            }
        );
    }
}

fn discard_whitespace<'a, F: 'a, O, E: ParseError<&'a [u8]>>(
    inner: F,
) -> impl FnMut(&'a [u8]) -> IResult<&'a [u8], O, E>
where
    F: Fn(&'a [u8]) -> IResult<&'a [u8], O, E>,
{
    delimited(multispace0, inner, multispace0)
}

fn parse_full_projection(input: &[u8]) -> IResult<&[u8], Vec<ProjectionEntry>> {
    let (input, projections) =
        separated_list0(tag(";"), discard_whitespace(parse_projection_line))(input)?;
    Ok((input, projections))
}

fn parse_rw(input: &[u8]) -> IResult<&[u8], FileAccess> {
    let (input, access) = map(alt((tag("rw"), tag("r"))), |res: &[u8]| match res {
        b"rw" => FileAccess::ReadWrite,
        b"r" => FileAccess::Read,
        _ => unreachable!(),
    })(input)?;
    Ok((input, access))
}

fn parse_projection_line(input: &[u8]) -> IResult<&[u8], ProjectionEntry> {
    let (input, projection) = alt((parse_portal, parse_file, parse_directory))(input)?;
    Ok((input, projection))
}

fn parse_file(input: &[u8]) -> IResult<&[u8], ProjectionEntry> {
    let (input, _f) = tag("f(")(input)?;
    let (input, _) = peek(tag("/"))(input)?;
    let (input, name) = take_until1("|")(input)?;
    let (input, _) = tag("|")(input)?;
    let (input, source) = take_until1("|")(input)?;
    let (input, _) = tag("|")(input)?;
    let (input, access) = parse_rw(input)?;
    let (input, _) = tag(")")(input)?;
    Ok((
        input,
        ProjectionEntry::File {
            name: RawOsString::assert_from_raw_vec(name.to_vec())
                .into_os_string()
                .into(),
            source: RawOsString::assert_from_raw_vec(source.to_vec())
                .into_os_string()
                .into(),
            access,
        },
    ))
}

fn parse_portal(input: &[u8]) -> IResult<&[u8], ProjectionEntry> {
    let (input, _p) = tag("p(")(input)?;
    let (input, _) = peek(tag("/"))(input)?;
    let (input, name) = take_until1("|")(input)?;
    let (input, _) = tag("|")(input)?;
    let (input, source) = take_until1("|")(input)?;
    let (input, _) = tag("|")(input)?;
    let (input, access) = parse_rw(input)?;
    let (input, _) = tag("|")(input)?;
    let (input, protect_str) = take_until1("|")(input)?;
    let (_, protect) = separated_list0(tag(":"), take_until(":"))(protect_str)?;
    let (input, _) = tag("|")(input)?;
    let (input, _) = tag(")")(input)?;
    Ok((
        input,
        ProjectionEntry::Portal {
            name: RawOsString::assert_from_raw_vec(name.to_vec())
                .into_os_string()
                .into(),
            source: RawOsString::assert_from_raw_vec(source.to_vec())
                .into_os_string()
                .into(),
            access,
            protect: protect
                .into_iter()
                .map(|p| {
                    RawOsString::assert_from_raw_vec(p.to_vec())
                        .into_os_string()
                        .into()
                })
                .collect(),
        },
    ))
}

fn parse_directory(input: &[u8]) -> IResult<&[u8], ProjectionEntry> {
    let (input, _f) = tag("d(")(input)?;
    let (input, _) = peek(tag("/"))(input)?;
    let (input, name) = take_until1("|")(input)?;
    let (input, _) = tag("|")(input)?;
    let (input, _) = tag(")")(input)?;
    Ok((
        input,
        ProjectionEntry::Directory {
            name: RawOsString::assert_from_raw_vec(name.to_vec())
                .into_os_string()
                .into(),
        },
    ))
}
