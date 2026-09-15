//! Web addresses: the host a URL points at, and the site it belongs to.

use std::net::IpAddr;

/// The lower-case host of a web address: `https://Accounts.Google.com/x` gives
/// `accounts.google.com`. An address without a scheme counts as a web address; other schemes,
/// like `androidapp://`, give none.
pub fn host_of(url: &str) -> Option<String> {
    let lower = url.trim().to_lowercase();
    let rest = match lower.split_once("://") {
        Some(("http" | "https", rest)) => rest,
        Some(_) => return None,
        None => lower.as_str(),
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_and_port = authority.rsplit('@').next()?;
    if host_and_port.starts_with('[') {
        return None;
    }
    let host = host_and_port.split(':').next()?.trim_end_matches('.');
    let valid = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '.')
        && (host.contains('.') || host == "localhost");
    valid.then(|| host.to_owned())
}

/// The registrable domain of a host, from the Public Suffix List: `accounts.google.com` and
/// `mail.google.com` both give `google.com`, while `a.github.io` and `b.github.io` stay apart.
/// IP addresses and hosts without a dot are their own site.
pub fn site_of(host: &str) -> String {
    if host.parse::<IpAddr>().is_ok() || !host.contains('.') {
        return host.to_owned();
    }
    psl::domain_str(host).unwrap_or(host).to_owned()
}
