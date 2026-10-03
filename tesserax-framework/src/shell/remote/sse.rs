//! Incremental parser of a `text/event-stream` body (the subset the HTTP
//! shell sends: `id:`, `event:`, `data:`, comments).

/// One dispatched SSE message.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SseMessage {
    pub(crate) event: Option<String>,
    pub(crate) data: String,
}

/// Feeds on body chunks; yields complete messages.
#[derive(Debug)]
pub(crate) struct SseParser {
    line: Vec<u8>,
    event: Option<String>,
    data: Option<String>,
    max: usize,
}

/// A line or message grew past the parser's bound, or was not UTF-8.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SseError;

impl SseParser {
    /// A parser refusing lines and messages longer than `max` bytes.
    pub(crate) fn new(max: usize) -> Self {
        Self {
            line: Vec::new(),
            event: None,
            data: None,
            max,
        }
    }

    /// Consumes `chunk`, returning every message it completed.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseMessage>, SseError> {
        let mut out = Vec::new();
        for &byte in chunk {
            if byte != b'\n' {
                if self.line.len() >= self.max {
                    return Err(SseError);
                }
                self.line.push(byte);
                continue;
            }
            if self.line.last() == Some(&b'\r') {
                self.line.pop();
            }
            let line = std::mem::take(&mut self.line);
            let line = String::from_utf8(line).map_err(|_| SseError)?;
            if line.is_empty() {
                if let Some(data) = self.data.take() {
                    out.push(SseMessage {
                        event: self.event.take(),
                        data,
                    });
                }
                self.event = None;
                continue;
            }
            if line.starts_with(':') {
                continue;
            }
            let (field, value) = match line.split_once(':') {
                Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
                None => (line.as_str(), ""),
            };
            match field {
                "event" => self.event = Some(value.to_owned()),
                "data" => match &mut self.data {
                    Some(data) => {
                        if data.len() + 1 + value.len() > self.max {
                            return Err(SseError);
                        }
                        data.push('\n');
                        data.push_str(value);
                    }
                    None => self.data = Some(value.to_owned()),
                },
                _ => {}
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_split_messages_named_events_and_comments() {
        let mut p = SseParser::new(1024);
        assert_eq!(p.push(b": keep-alive\n\nid: 1\nda").unwrap(), []);
        let got = p
            .push(b"ta: {\"a\":1}\n\nevent: resync\ndata: {}\r\n\r\n")
            .unwrap();
        assert_eq!(
            got,
            [
                SseMessage {
                    event: None,
                    data: "{\"a\":1}".into()
                },
                SseMessage {
                    event: Some("resync".into()),
                    data: "{}".into()
                },
            ]
        );
    }

    #[test]
    fn refuses_oversized_lines() {
        let mut p = SseParser::new(8);
        assert_eq!(p.push(b"data: 0123456789\n"), Err(SseError));
    }
}
