//! Target allowlist. Both the app and the runner check every URL against it,
//! including the addresses its hostname resolves to right before a job.

use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// Lowercase hostnames, or `*.example.dk` for any subdomain.
    hosts: Vec<String>,
    networks: Vec<(IpAddr, u8)>,
}

fn parse_network(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, len) = match s.split_once('/') {
        Some((ip, len)) => (ip.parse::<IpAddr>().ok()?, len.parse::<u8>().ok()?),
        None => {
            let ip = s.parse::<IpAddr>().ok()?;
            (ip, if ip.is_ipv4() { 32 } else { 128 })
        }
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (len <= max).then_some((ip, len))
}

fn in_network(ip: IpAddr, (net, len): (IpAddr, u8)) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// Addresses that are never scanned unless their network is listed explicitly.
fn is_special(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

impl Scope {
    /// Parses a comma- or space-separated list such as
    /// `*.schwabejss.dk, internaltest.example.dk, 10.0.20.0/24`.
    pub fn parse(list: &str) -> Result<Self, String> {
        let mut scope = Self::default();
        for item in list
            .split([',', ' ', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if let Some(net) = parse_network(item) {
                scope.networks.push(net);
            } else if item.contains('/') || item.contains(':') {
                return Err(format!("Invalid network in allowlist: {item}"));
            } else {
                let host = item.to_lowercase();
                let bare = host.strip_prefix("*.").unwrap_or(&host);
                if bare.is_empty()
                    || bare.contains('*')
                    || !bare
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
                {
                    return Err(format!("Invalid host in allowlist: {item}"));
                }
                scope.hosts.push(host);
            }
        }
        Ok(scope)
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.networks.is_empty()
    }

    fn host_matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_lowercase();
        self.hosts.iter().any(|p| match p.strip_prefix("*.") {
            Some(domain) => host.ends_with(&format!(".{domain}")),
            None => *p == host,
        })
    }

    fn ip_allowed(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|n| in_network(ip, *n))
    }

    /// Checks the URL's host against the allowlist without resolving it.
    pub fn check_host(&self, url: &url::Url) -> Result<(), String> {
        if self.is_empty() {
            return Err(
                "No targets are allowed yet. Add hosts or networks to SCOPE_ALLOWLIST.".into(),
            );
        }
        let ok = match url.host() {
            Some(url::Host::Domain(d)) => self.host_matches(d),
            Some(url::Host::Ipv4(ip)) => self.ip_allowed(IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => self.ip_allowed(IpAddr::V6(ip)),
            None => false,
        };
        if ok {
            Ok(())
        } else {
            Err(format!(
                "{} is not in the allowlist",
                url.host_str().unwrap_or("?")
            ))
        }
    }

    /// Checks resolved addresses: with networks listed, every address must be
    /// inside one; without, loopback and link-local addresses are refused so a
    /// DNS answer can't redirect a scan to the runner itself or cloud metadata.
    pub fn check_addresses(&self, host: &str, addrs: &[IpAddr]) -> Result<(), String> {
        if addrs.is_empty() {
            return Err(format!("{host} does not resolve"));
        }
        for &ip in addrs {
            if self.ip_allowed(ip) {
                continue;
            }
            if !self.networks.is_empty() {
                return Err(format!(
                    "{host} resolves to {ip}, which is outside the allowed networks"
                ));
            }
            if is_special(ip) {
                return Err(format!(
                    "{host} resolves to {ip}; add that network to the allowlist to scan it"
                ));
            }
        }
        Ok(())
    }

    /// Full check: hostname, then the addresses it resolves to right now.
    pub async fn check_url(&self, url: &url::Url) -> Result<Vec<IpAddr>, String> {
        self.check_host(url)?;
        let host = url.host_str().ok_or("URL has no host")?;
        let port = url.port_or_known_default().unwrap_or(443);
        let lookup_host = host.trim_start_matches('[').trim_end_matches(']');
        let addrs: Vec<IpAddr> = tokio::net::lookup_host((lookup_host, port))
            .await
            .map_err(|e| format!("Cannot resolve {host}: {e}"))?
            .map(|a| a.ip())
            .collect();
        self.check_addresses(host, &addrs)?;
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    #[test]
    fn matches_hosts_wildcards_and_networks() {
        let s = Scope::parse("*.schwabejss.dk, exact.example.dk 10.0.20.0/24,fd00::/8").unwrap();
        assert!(s
            .check_host(&url("https://internaltest.schwabejss.dk/"))
            .is_ok());
        assert!(s.check_host(&url("https://a.b.schwabejss.dk/")).is_ok());
        assert!(s.check_host(&url("https://schwabejss.dk/")).is_err());
        assert!(s.check_host(&url("https://evilschwabejss.dk/")).is_err());
        assert!(s.check_host(&url("https://EXACT.example.dk/")).is_ok());
        assert!(s.check_host(&url("https://other.example.dk/")).is_err());
        assert!(s.check_host(&url("http://10.0.20.7:8080/")).is_ok());
        assert!(s.check_host(&url("http://10.0.21.7/")).is_err());
        assert!(s.check_host(&url("http://[fd12::1]/")).is_ok());
    }

    #[test]
    fn rejects_bad_entries_and_empty_scope() {
        assert!(Scope::parse("10.0.0.0/33").is_err());
        assert!(Scope::parse("exa*mple.dk").is_err());
        assert!(Scope::parse("")
            .unwrap()
            .check_host(&url("https://a.dk"))
            .is_err());
    }

    #[test]
    fn resolved_addresses_must_stay_in_scope() {
        let with_nets = Scope::parse("*.example.dk,10.0.20.0/24").unwrap();
        let inside: IpAddr = "10.0.20.5".parse().unwrap();
        let outside: IpAddr = "10.9.9.9".parse().unwrap();
        assert!(with_nets.check_addresses("a.example.dk", &[inside]).is_ok());
        assert!(with_nets
            .check_addresses("a.example.dk", &[inside, outside])
            .is_err());

        let hosts_only = Scope::parse("*.example.dk").unwrap();
        assert!(hosts_only
            .check_addresses("a.example.dk", &["93.184.215.14".parse().unwrap()])
            .is_ok());
        for bad in ["127.0.0.1", "169.254.169.254", "::1", "fe80::1"] {
            assert!(
                hosts_only
                    .check_addresses("a.example.dk", &[bad.parse().unwrap()])
                    .is_err(),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn check_url_resolves_names() {
        let s = Scope::parse("localhost").unwrap();
        assert!(s
            .check_url(&url("http://localhost:8080/"))
            .await
            .unwrap_err()
            .contains("add that network"));
        let s = Scope::parse("localhost,127.0.0.0/8,::1").unwrap();
        assert!(s.check_url(&url("http://localhost:8080/")).await.is_ok());
    }
}
