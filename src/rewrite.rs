use anyhow::{bail, ensure, Result};

#[derive(Clone, Debug)]
pub struct Mapping {
    pub public: String,
    pub upstream: String,
    pub public_host: String,
    pub upstream_host: String,
    pub public_port: u16,
    pub upstream_port: u16,
}
fn authority(s: &str) -> Result<(String, u16)> {
    ensure!(
        s.is_ascii()
            && !s.bytes().any(|c| c <= 32 || c == 127)
            && !s.contains(['/', '?', '#', '@']),
        "invalid authority"
    );
    let u = url::Url::parse(&format!("https://{s}/"))?;
    ensure!(u.host_str().is_some(), "missing host");
    Ok((
        u.host_str().unwrap().to_ascii_lowercase(),
        u.port_or_known_default().unwrap(),
    ))
}
impl Mapping {
    pub fn new(public: &str, upstream: &str) -> Result<Self> {
        let (public_host, public_port) = authority(public)?;
        let (upstream_host, upstream_port) = authority(upstream)?;
        Ok(Self {
            public: public.into(),
            upstream: upstream.into(),
            public_host,
            upstream_host,
            public_port,
            upstream_port,
        })
    }
    pub fn is_public(&self, s: &str) -> bool {
        authority(s).is_ok_and(|x| x == (self.public_host.clone(), self.public_port))
    }
    fn map_url(&self, s: &str, response: bool) -> String {
        let begin = if s.starts_with("https://") {
            8
        } else if s.starts_with("//") {
            2
        } else {
            return s.into();
        };
        let end = s[begin..]
            .find(['/', '?', '#'])
            .map_or(s.len(), |n| begin + n);
        let expected = if response {
            (&self.upstream_host, self.upstream_port)
        } else {
            (&self.public_host, self.public_port)
        };
        if authority(&s[begin..end]).is_ok_and(|(h, p)| h == *expected.0 && p == expected.1) {
            format!(
                "{}{}{}",
                &s[..begin],
                if response {
                    &self.public
                } else {
                    &self.upstream
                },
                &s[end..]
            )
        } else {
            s.into()
        }
    }
    pub fn value(&self, name: &[u8], value: &[u8], response: bool) -> Result<Vec<u8>> {
        let lower = name.to_ascii_lowercase();
        let relevant = if response {
            lower == b"set-cookie" || lower == b"location"
        } else {
            matches!(
                lower.as_slice(),
                b"host" | b":authority" | b"origin" | b"referer"
            )
        };
        if !relevant {
            return Ok(value.to_vec());
        }
        let s = std::str::from_utf8(value)?;
        let leading = s.len() - s.trim_start_matches([' ', '\t']).len();
        let end = s.trim_end_matches([' ', '\t']).len();
        ensure!(end >= leading, "empty mapped header");
        let trimmed = &s[leading..end];
        let mapped = match lower.as_slice() {
            b"host" | b":authority" => {
                ensure!(
                    self.is_public(trimmed),
                    "authority does not match configured B"
                );
                self.upstream.clone()
            }
            b"origin" | b"referer" | b"location" => self.map_url(trimmed, response),
            b"set-cookie" => {
                // Only cookie attributes, never the first name=value pair or its value.
                let mut parts = trimmed.split(';');
                let mut out = parts.next().unwrap_or("").to_string();
                for part in parts {
                    out.push(';');
                    if let Some(eq) = part.find('=') {
                        if part[..eq].trim().eq_ignore_ascii_case("domain") {
                            let raw = &part[eq + 1..];
                            let v = raw.trim();
                            if v.trim_start_matches('.')
                                .eq_ignore_ascii_case(&self.upstream_host)
                            {
                                let ws = raw.len() - raw.trim_start().len();
                                let tail = raw.trim_end().len();
                                out.push_str(&part[..eq + 1]);
                                out.push_str(&raw[..ws]);
                                if v.starts_with('.') {
                                    out.push('.')
                                }
                                out.push_str(&self.public_host);
                                out.push_str(&raw[tail..]);
                                continue;
                            }
                        }
                    }
                    out.push_str(part);
                }
                out
            }
            _ => unreachable!(),
        };
        Ok(format!("{}{}{}", &s[..leading], mapped, &s[end..]).into_bytes())
    }
    /// Changes only selected field values. Header spelling/order/whitespace stays intact.
    pub fn h1_head(&self, head: &[u8], response: bool) -> Result<Vec<u8>> {
        ensure!(head.ends_with(b"\r\n\r\n"), "invalid HTTP head");
        let mut out = Vec::with_capacity(head.len());
        let mut lines = head.split(|b| *b == b'\n');
        let first = lines.next().unwrap();
        out.extend_from_slice(first);
        out.push(b'\n');
        let mut hosts = 0;
        for line in lines {
            if line.is_empty() {
                break;
            }
            ensure!(line.ends_with(b"\r"), "bare LF");
            let line = &line[..line.len() - 1];
            if line.is_empty() {
                out.extend_from_slice(b"\r\n");
                break;
            }
            ensure!(
                !line.starts_with(b" ") && !line.starts_with(b"\t"),
                "obs-fold unsupported"
            );
            let colon = line
                .iter()
                .position(|b| *b == b':')
                .ok_or_else(|| anyhow::anyhow!("invalid header"))?;
            let name = &line[..colon];
            ensure!(
                !name.is_empty()
                    && name
                        .iter()
                        .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(c)),
                "invalid header name"
            );
            if name.eq_ignore_ascii_case(b"host") {
                hosts += 1
            }
            out.extend_from_slice(&line[..colon + 1]);
            out.extend(self.value(name, &line[colon + 1..], response)?);
            out.extend_from_slice(b"\r\n");
        }
        if !response && hosts != 1 {
            bail!("exactly one Host is required")
        }
        Ok(out)
    }
}

pub fn header_names(head: &[u8]) -> Vec<String> {
    head.split(|b| *b == b'\n')
        .skip(1)
        .filter_map(|line| {
            line.iter()
                .position(|b| *b == b':')
                .map(|n| String::from_utf8_lossy(&line[..n]).into_owned())
        })
        .collect()
}
