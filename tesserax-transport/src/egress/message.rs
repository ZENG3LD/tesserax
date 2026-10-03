//! [`EmailMessage`] and its RFC 5322 form.

use base64::Engine as _;

use super::smtp::SmtpError;

/// One outgoing mail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailMessage {
    /// Envelope sender and `From:` header (bare address).
    pub from: String,
    /// `To:` recipients.
    pub to: Vec<String>,
    /// `Cc:` recipients.
    pub cc: Vec<String>,
    /// Blind recipients: in the envelope only, never in a header.
    pub bcc: Vec<String>,
    /// Subject (non-ASCII is RFC 2047 encoded).
    pub subject: String,
    /// Body; line breaks of any style are sent as CRLF.
    pub body: String,
    /// `text/html` instead of `text/plain`.
    pub body_is_html: bool,
}

impl EmailMessage {
    /// Plain-text mail to one recipient.
    pub fn text(
        from: impl Into<String>,
        to: impl Into<String>,
        subject: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            from: from.into(),
            to: vec![to.into()],
            cc: Vec::new(),
            bcc: Vec::new(),
            subject: subject.into(),
            body: body.into(),
            body_is_html: false,
        }
    }

    /// HTML mail to one recipient.
    pub fn html(
        from: impl Into<String>,
        to: impl Into<String>,
        subject: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        let mut m = Self::text(from, to, subject, body);
        m.body_is_html = true;
        m
    }

    /// Every envelope recipient: to, cc, bcc.
    pub(crate) fn recipients(&self) -> impl Iterator<Item = &String> {
        self.to.iter().chain(&self.cc).chain(&self.bcc)
    }

    /// Refuses what would let a field inject SMTP commands or headers.
    pub(crate) fn validate(&self) -> Result<(), SmtpError> {
        check_address("from", &self.from)?;
        for a in self.recipients() {
            check_address("recipient", a)?;
        }
        if self.recipients().next().is_none() {
            return Err(SmtpError::InvalidMessage("no recipients".into()));
        }
        if self.subject.chars().any(|c| c == '\r' || c == '\n') {
            return Err(SmtpError::InvalidMessage(
                "subject contains a line break".into(),
            ));
        }
        Ok(())
    }
}

fn check_address(what: &str, a: &str) -> Result<(), SmtpError> {
    if a.is_empty()
        || a.chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '<' || c == '>')
    {
        return Err(SmtpError::InvalidMessage(format!(
            "{what} address {a:?} is empty or contains a control, space or angle bracket"
        )));
    }
    Ok(())
}

/// The RFC 5322 text of `m` (headers, blank line, body as given). `Bcc`
/// recipients are left out of the headers. Fails on fields that could
/// inject headers or SMTP commands.
pub fn build_rfc2822(m: &EmailMessage) -> Result<String, SmtpError> {
    m.validate()?;
    let mut out = format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\n",
        from = m.from,
        to = m.to.join(", "),
        subject = encode_header(&m.subject),
    );
    if !m.cc.is_empty() {
        out.push_str(&format!("Cc: {}\r\n", m.cc.join(", ")));
    }
    if m.body_is_html {
        out.push_str("Content-Type: text/html; charset=utf-8\r\n\r\n");
    } else {
        out.push_str("Content-Type: text/plain; charset=utf-8\r\n\r\n");
    }
    out.push_str(&m.body);
    Ok(out)
}

/// RFC 2047 B-encoding for a non-ASCII header value.
fn encode_header(s: &str) -> String {
    if s.is_ascii() {
        return s.to_owned();
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(s.as_bytes());
    format!("=?UTF-8?B?{b64}?=")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_text_message() {
        let m = EmailMessage::text("a@b.com", "c@d.com", "hi", "body");
        let s = build_rfc2822(&m).unwrap();
        assert!(s.contains("From: a@b.com"));
        assert!(s.contains("To: c@d.com"));
        assert!(s.contains("Subject: hi"));
        assert!(s.contains("text/plain"));
        assert!(s.ends_with("body"));
    }

    #[test]
    fn build_html_message() {
        let m = EmailMessage::html("a@b.com", "c@d.com", "hi", "<b>x</b>");
        let s = build_rfc2822(&m).unwrap();
        assert!(s.contains("text/html"));
        assert!(s.contains("<b>x</b>"));
    }

    #[test]
    fn cc_is_a_header_bcc_is_not() {
        let mut m = EmailMessage::text("a@b.com", "c@d.com", "hi", "body");
        m.cc = vec!["e@f.com".into()];
        m.bcc = vec!["g@h.com".into()];
        let s = build_rfc2822(&m).unwrap();
        assert!(s.contains("Cc: e@f.com"));
        assert!(
            !s.contains("g@h.com"),
            "blind recipients never appear in headers"
        );
        assert_eq!(m.recipients().count(), 3);
    }

    #[test]
    fn non_ascii_subject_is_encoded() {
        let m = EmailMessage::text("a@b.com", "c@d.com", "Привет", "body");
        let s = build_rfc2822(&m).unwrap();
        assert!(s.contains("=?UTF-8?B?"));
        assert!(!s.contains("Subject: Привет"));
    }

    #[test]
    fn injection_attempts_are_refused() {
        let base = EmailMessage::text("a@b.com", "c@d.com", "hi", "body");
        let mut bad_subject = base.clone();
        bad_subject.subject = "hi\r\nBcc: x@y.com".into();
        let mut bad_from = base.clone();
        bad_from.from = "a@b.com>\r\nRCPT TO:<x@y.com".into();
        let mut bad_to = base.clone();
        bad_to.to = vec!["c@d.com\n".into()];
        let mut none = base.clone();
        none.to.clear();
        for m in [bad_subject, bad_from, bad_to, none] {
            assert!(
                matches!(build_rfc2822(&m), Err(SmtpError::InvalidMessage(_))),
                "{m:?}"
            );
        }
    }
}
