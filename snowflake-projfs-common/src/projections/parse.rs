use crate::projections::{FileAccess, Projection};
use nom::branch::alt;
use nom::bytes::complete::{tag, take_until, take_until1};
use nom::combinator::{map, not};
use nom::multi::{many0, separated_list0};
use nom::{IResult, Parser};
use os_str_bytes::RawOsString;
use std::ffi::OsString;
use std::path::PathBuf;

pub fn parse_projection(s: &[u8]) -> Vec<Projection> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use crate::projections::parse::{parse_directory, parse_file, parse_portal, parse_projection};
    use crate::projections::{FileAccess, Projection};
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::str::FromStr;

    #[test]
    fn parse_projection_string() {
        let projection = br#"
f(hello.world|C:\test.txt|r);
d(directory|f(hello.world|C:\test.txt|r):f(hello.world|C:\test.txt|rw):);
p(portal|C:\test|rw|protected:file:);
        "#;

        let parsed = parse_projection(projection);
        assert_eq!(
            parsed,
            vec![Projection::File {
                name: OsString::from_str("hello.world").unwrap(),
                source: PathBuf::from_str("C:\\test.txt").unwrap(),
                access: FileAccess::Read
            }]
        );
    }

    #[test]
    fn parse_file_test() {
        let projection = br#"f(hello.world|C:\test.txt|r)"#;

        let (_, parsed) = parse_file(projection).unwrap();
        assert_eq!(
            parsed,
            Projection::File {
                name: OsString::from_str("hello.world").unwrap(),
                source: PathBuf::from_str("C:\\test.txt").unwrap(),
                access: FileAccess::Read
            }
        );
    }

    #[test]
    fn parse_portal_test() {
        let projection = br#"p(portal|C:\test|rw|protected:file:);"#;
        let (_, parsed) = parse_portal(projection).unwrap();
        assert_eq!(
            parsed,
            Projection::Portal {
                name: OsString::from_str("portal").unwrap(),
                source: PathBuf::from_str("C:\\test").unwrap(),
                access: FileAccess::ReadWrite,
                protect: vec![PathBuf::from("protected"), PathBuf::from("file"),]
            }
        );
    }
    #[test]
    fn parse_directory_test() {
        let projection =
            br#"d(directory|f(hello.world|C:\test.txt|r):f(hello.world|C:\test.txt|rw):);"#;
        let (_, parsed) = parse_directory(projection).unwrap();
        assert_eq!(
            parsed,
            Projection::Directory {
                name: "directory".parse().unwrap(),
                contents: vec![
                    Projection::File {
                        name: "hello.world".parse().unwrap(),
                        source: "C:\\test.txt".parse().unwrap(),
                        access: FileAccess::Read
                    },
                    Projection::File {
                        name: "hello.world".parse().unwrap(),
                        source: "C:\\test.txt".parse().unwrap(),
                        access: FileAccess::ReadWrite
                    }
                ]
            }
        );
    }
}

fn parse_rw(input: &[u8]) -> IResult<&[u8], FileAccess> {
    let (input, access) = map(alt((tag("rw"), tag("r"))), |res: &[u8]| match res {
        b"rw" => FileAccess::ReadWrite,
        b"r" => FileAccess::Read,
        _ => unreachable!(),
    })(input)?;
    Ok((input, access))
}

fn parse_projection_line(input: &[u8]) -> IResult<&[u8], Projection> {
    let (input, projection) = alt((parse_file, parse_portal, parse_directory))(input)?;
    Ok((input, projection))
}

fn parse_file(input: &[u8]) -> IResult<&[u8], Projection> {
    let (input, _f) = tag("f(")(input)?;
    let (input, name) = take_until1("|")(input)?;
    let (input, _) = tag("|")(input)?;
    let (input, source) = take_until1("|")(input)?;
    let (input, _) = tag("|")(input)?;
    let (input, access) = parse_rw(input)?;
    let (input, _) = tag(")")(input)?;
    Ok((
        input,
        Projection::File {
            name: RawOsString::assert_from_raw_vec(name.to_vec()).into_os_string(),
            source: RawOsString::assert_from_raw_vec(source.to_vec())
                .into_os_string()
                .into(),
            access,
        },
    ))
}

fn parse_portal(input: &[u8]) -> IResult<&[u8], Projection> {
    let (input, _p) = tag("p(")(input)?;
    let (input, name) = take_until1("|")(input)?;
    let (input, _) = tag("|")(input)?;
    let (input, source) = take_until1("|")(input)?;
    let (input, _) = tag("|")(input)?;
    let (input, access) = parse_rw(input)?;
    let (input, _) = tag("|")(input)?;
    let (input, protect) = separated_list0(tag(":"), take_until(":"))(input)?;
    let (input, _) = tag(":")(input)?;
    let (input, _) = tag(")")(input)?;
    Ok((
        input,
        Projection::Portal {
            name: RawOsString::assert_from_raw_vec(name.to_vec()).into_os_string(),
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

fn parse_directory(input: &[u8]) -> IResult<&[u8], Projection> {
    let (input, _f) = tag("d(")(input)?;
    let (input, name) = take_until1("|")(input)?;
    let (input, _) = tag("|")(input)?;
    let (input, contents) = separated_list0(tag(":"), parse_projection_line)(input)?;
    let (input, _) = tag(":")(input)?;
    let (input, _) = tag(")")(input)?;
    Ok((
        input,
        Projection::Directory {
            name: RawOsString::assert_from_raw_vec(name.to_vec()).into_os_string(),
            contents,
        },
    ))
}
