use std::{
    error::Error,
    fmt,
    future::Future,
    io::{self, Write},
    sync::LazyLock,
};

use regex::bytes::{Captures, Regex};

pub trait Transport {
    fn send(&mut self, message: Message) -> impl Future<Output = io::Result<()>>;
    fn receive(&mut self) -> impl Future<Output = io::Result<Option<Message>>>;
}

#[derive(Debug)]
pub struct Message {
    prefix: Option<Prefix>,
    command: Command,
    parameters: Option<Vec<String>>,
    last_parameter: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Command {
    Numeric(u32),
    General(String),
}

#[derive(Debug)]
pub enum Prefix {
    // we could hypothetically handle all the forms of server
    // but these are generally treated as a name, so no particular need
    Server(String),
    User(UserMask),
}

#[derive(Debug)]
pub struct UserMask {
    pub nickname: String,
    pub user: String,
    pub server: String,
}

#[derive(Debug)]
pub struct ProtocolError {
    source: Option<Box<dyn Error + Send + Sync>>,
    reason: &'static str,
}

impl Error for ProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &_)
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason)
    }
}

impl Message {
    pub fn new(
        prefix: Option<Prefix>,
        command: Command,
        parameters: Option<Vec<String>>,
        last_parameter: Option<String>,
    ) -> Result<Message, ProtocolError> {
        fn sp(s: &str) -> bool {
            // it may be more correct to check for "\r\n", but, since it's invalid anyway to have those chars,
            // might as well do it this way
            s.contains(' ') || s.contains('\r') || s.contains('\n')
        }

        match prefix {
            Some(Prefix::Server(ref s)) if sp(s) => Err(ProtocolError {
                reason: "Prefix has spaces or crlf",
                source: None,
            }),
            Some(Prefix::User(UserMask {
                ref nickname,
                ref user,
                ref server,
            })) if sp(nickname) || sp(user) || sp(server) => Err(ProtocolError {
                reason: "Prefix has spaces or crlf",
                source: None,
            }),
            _ => Ok(()),
        }?;

        match command {
            Command::General(ref c) if sp(c) => Err(ProtocolError {
                reason: "Command has spaces or crlf",
                source: None,
            }),
            _ => Ok(()),
        }?;

        match parameters {
            Some(ref p) if p.iter().any(|p| sp(p) || p.starts_with(':')) => Err(ProtocolError {
                reason: "Prefix has spaces, crlf, or starts with colon",
                source: None,
            }),
            Some(ref p) if p.len() > 14 => Err(ProtocolError {
                reason: "More than 14 parameters present",
                source: None,
            }),
            _ => Ok(()),
        }?;

        match last_parameter {
            Some(ref s) if s.contains("\r\n") => Err(ProtocolError {
                reason: "Last parameter has crlf",
                source: None,
            }),
            _ => Ok(()),
        }?;

        if Self::calc_len(&prefix, &command, &parameters, &last_parameter) > 512 {
            Err(ProtocolError {
                reason: "Entire message is more than 512 bytes, including crlf.",
                source: None,
            })
        } else {
            Ok(Message {
                prefix,
                command,
                parameters,
                last_parameter,
            })
        }
    }

    pub fn new_unchecked(
        prefix: Option<Prefix>,
        command: Command,
        parameters: Option<Vec<String>>,
        last_parameter: Option<String>,
    ) -> Message {
        Message {
            prefix,
            command,
            parameters,
            last_parameter,
        }
    }

    pub fn prefix(&self) -> &Option<Prefix> {
        &self.prefix
    }

    pub fn command(&self) -> &Command {
        &self.command
    }

    pub fn parameters(&self) -> &Option<Vec<String>> {
        &self.parameters
    }

    pub fn last_parameter(&self) -> &Option<String> {
        &self.last_parameter
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let len = Self::calc_len(
            &self.prefix,
            &self.command,
            &self.parameters,
            &self.last_parameter,
        );
        if len > 512 {
            return Err(ProtocolError {
                reason: "Entire message is more than 512 bytes, including crlf.",
                source: None,
            });
        }

        let mut b = Vec::with_capacity(len);

        match &self.prefix {
            Some(Prefix::Server(s)) => write!(b, ":{} ", s),
            Some(Prefix::User(UserMask {
                nickname,
                user,
                server,
            })) => write!(b, ":{}!{}@{}", nickname, user, server),
            _ => Ok(()),
        }
        .map_err(|e| ProtocolError {
            reason: "Unable to format prefix.",
            source: Some(Box::new(e)),
        })?;

        match &self.command {
            Command::Numeric(n) => write!(b, "{:03}", n),
            Command::General(c) => b.write_all(c.as_bytes()),
        }
        .map_err(|e| ProtocolError {
            reason: "Unable to format command.",
            source: Some(Box::new(e)),
        })?;

        if let Some(p) = &self.parameters {
            for p in p.iter() {
                write!(b, " {}", p).map_err(|e| ProtocolError {
                    reason: "Unable to format parameters.",
                    source: Some(Box::new(e)),
                })?;
            }
        };

        if let Some(p) = &self.last_parameter {
            write!(b, " :{}", p).map_err(|e| ProtocolError {
                reason: "Unable to format last parameter.",
                source: Some(Box::new(e)),
            })?;
        }

        Ok(b)
    }

    pub fn parse(input: &[u8]) -> Result<Option<(Message, usize)>, ProtocolError> {
        // if we don't have a complete line, there's simply incomplete data in the buffer
        // which is not an error
        if !input.windows(2).any(|w| w == b"\r\n") {
            return Ok(None);
        }

        // this is technically more permissive than the spec
        // but, since we're expecting to parse valid messages, this is fine
        // and is also why we use new_unchecked (and for perf)
        static R: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(
                r"^(?x)
                (?::(?: # prefix
                    (?:(?<nick>[^!]+)!(?<user>[^@]+)@(?<server>[^\ ]+))
                    | (?<serverprefix>[^\ ]+)
                )\ +)?

                (?<command>[^\ ]+)

                # to make sure we dont capture starting and ending spaces,
                # we match one or more spaces before the first parameter,
                # then capture zero or more spaces before each parameter,
                # such that only the 0th parameter will have zero prior spaces
                (?:\ +
                    (?<parameters>
                        (?:\ *[^:\ ][^\ ]*){1,14}
                    )
                )?

                # if 14 params, then the colon is optional
                # if >0 and <14, the colon is present
                # in either case, due to how we match the initial parameters, this regex is sufficient
                (?:
                    \ +:?
                    (?<lastparam>[^\r\n]*)
                )?
                \r\n
                ",
            )
            .unwrap()
        });

        // it's a String mainly because we generally use it as such and we can do a lossy conversion
        // and, one way or another, when returning from parse, we need to clone what comes out of the capture
        // this ends up being slightly inefficient if we parse it again,
        // but, since we still want the lossy conversion, oh well
        fn cap(c: &Captures, name: &str) -> Option<String> {
            c.name(name)
                .map(|m| String::from_utf8_lossy(m.as_bytes()).to_string())
        }

        // i have doubts as to whether or not this style is better than the more procedural version
        // but this was an attempt to push the style hard. we can change it later if desired.
        R.captures(input)
            .filter(|c| c.get(0).map(|m| !m.is_empty()).unwrap_or(false))
            .map_or(Err(ProtocolError{reason: "Unable parse message from bytes.", source: None}), |c| Ok(Some((
                Message::new_unchecked(
                    cap(&c, "nick")
                        .map(|n| Prefix::User(UserMask {
                            nickname: n,
                            user: cap(&c, "user").expect("If nick present, this must be present according to regex."),
                            server: cap(&c, "server").expect("If nick present, this must be present according to regex.")
                        }))
                        .or_else(|| cap(&c, "serverprefix").map(Prefix::Server)),
                    cap(&c, "command")
                        .map(|c| c.parse().map_or(Command::General(c), Command::Numeric))
                        .expect("The regex has matched, so this non-optional capture can be unwrapped."),
                    cap(&c, "parameters")
                        .map(|p| Some(p.split_ascii_whitespace()
                            .map(|p| p.to_string())
                            .collect::<Vec<String>>()))
                        .unwrap_or(None),
                    cap(&c, "lastparam"),
                ),
                c.get(0).unwrap().len(),
            ))))
    }

    fn calc_len(
        prefix: &Option<Prefix>,
        command: &Command,
        parameters: &Option<Vec<String>>,
        last_parameter: &Option<String>,
    ) -> usize {
        2 + // crlf
        match prefix {
            Some(Prefix::Server(s)) => s.len() + 2, // colon prefix + space
            Some(Prefix::User(UserMask {
                nickname,
                user,
                server,
            })) => nickname.len() + user.len() + server.len() + 4, // colon prefix, !, @, and space
            None => 0,
        } + match command {
            Command::General(s) => s.len(),
            Command::Numeric(_) => 3 //three digit number
        } + match parameters {
            // can consider the separating space a prefix
            Some(p) => p.iter().fold(0, |acc, cur| acc + cur.len() + 1),
            None => 0
        } + match last_parameter {
            Some(p) => p.len() + 2, // colon prefix, can consider the separating space a prefix
            None => 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_message() {
        let raw = b"COMMAND\r\n";

        let Ok(Some((message, _))) = Message::parse(raw) else {
            panic!("Unable to parse message")
        };

        assert_eq!(
            Message::new_unchecked(None, Command::General("COMMAND".to_string()), None, None),
            message
        );
    }

    #[test]
    fn parse_parameters() {
        let raw = b"COMMAND foo ba:r baz: :yay\r\n";

        let Ok(Some((message, _))) = Message::parse(raw) else {
            panic!("Unable to parse message")
        };

        assert_eq!(
            Message::new_unchecked(
                None,
                Command::General("COMMAND".to_string()),
                Some(vec![
                    "foo".to_string(),
                    "ba:r".to_string(),
                    "baz:".to_string()
                ]),
                Some("yay".to_string())
            ),
            message
        );
    }

    #[test]
    fn parse_over_fourteen_parameters() {
        let expected = Message::new_unchecked(
            None,
            Command::General("COMMAND".to_string()),
            Some(vec![
                "1".to_string(),
                "2".to_string(),
                "3".to_string(),
                "4".to_string(),
                "5".to_string(),
                "6".to_string(),
                "7".to_string(),
                "8".to_string(),
                "9".to_string(),
                "10".to_string(),
                "11".to_string(),
                "12".to_string(),
                "13".to_string(),
                "14".to_string(),
            ]),
            Some("15 16 17".to_string()),
        );

        let raw = b"COMMAND 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17\r\n";
        let Ok(Some((message, _))) = Message::parse(raw) else {
            panic!("Unable to parse message")
        };
        assert_eq!(expected, message);

        let raw = b"COMMAND 1 2 3 4 5 6 7 8 9 10 11 12 13 14 :15 16 17\r\n";
        let Ok(Some((message, _))) = Message::parse(raw) else {
            panic!("Unable to parse message")
        };
        assert_eq!(expected, message);
    }

    #[test]
    fn parse_server_prefix() {
        let raw = b":server-yay COMMAND\r\n";

        let Ok(Some((message, _))) = Message::parse(raw) else {
            panic!("Unable to parse message")
        };

        assert_eq!(
            Message::new_unchecked(
                Some(Prefix::Server("server-yay".to_string())),
                Command::General("COMMAND".to_string()),
                None,
                None
            ),
            message
        );
    }

    #[test]
    fn parse_user_prefix() {
        let raw = b":nick!user@server COMMAND\r\n";

        let Ok(Some((message, _))) = Message::parse(raw) else {
            panic!("Unable to parse message")
        };

        assert_eq!(
            Message::new_unchecked(
                Some(Prefix::User(UserMask {
                    nickname: "nick".to_string(),
                    user: "user".to_string(),
                    server: "server".to_string()
                })),
                Command::General("COMMAND".to_string()),
                None,
                None
            ),
            message
        );
    }

    // these impls arent meant for public use but are convenient to use here
    impl PartialEq for Message {
        fn eq(&self, other: &Self) -> bool {
            self.prefix == other.prefix
                && self.command == other.command
                && self.parameters == other.parameters
                && self.last_parameter == other.last_parameter
        }
    }
    impl PartialEq for Prefix {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Server(l0), Self::Server(r0)) => l0 == r0,
                (Self::User(l0), Self::User(r0)) => l0 == r0,
                _ => false,
            }
        }
    }
    impl PartialEq for UserMask {
        fn eq(&self, other: &Self) -> bool {
            self.nickname == other.nickname
                && self.user == other.user
                && self.server == other.server
        }
    }
}
