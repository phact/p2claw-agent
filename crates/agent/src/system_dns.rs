//! A DNS resolver for iroh backed by the operating system
//! (`getaddrinfo`).
//!
//! iroh's default resolver reads nameservers itself: from
//! `/etc/resolv.conf`, or on Android from the framework over JNI.
//! The agent running as a plain executable on Android has neither,
//! so iroh falls back to Google's public resolvers, which breaks on
//! networks that block outside DNS. Asking the OS instead uses
//! whatever DNS the network handed out.
//!
//! The agent builds its endpoint with `presets::Minimal` (no DNS
//! address lookup), so only A/AAAA lookups (relay hostnames, net
//! report probes) matter; TXT lookups report no response.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

use iroh::dns::{BoxIter, DnsError, Resolver, TxtRecordData};
use n0_error::{e, AnyError};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl SystemResolver {
    async fn lookup(host: String) -> Result<Vec<IpAddr>, DnsError> {
        // `lookup_host` needs a port; it plays no part in resolution.
        let addrs = tokio::net::lookup_host((host.as_str(), 0))
            .await
            .map_err(|err| e!(DnsError::Resolve, AnyError::from(err)))?;
        Ok(addrs.map(|addr| addr.ip()).collect())
    }
}

/// Keeps the addresses `pick` selects; an empty result is `NoResponse`,
/// matching iroh's own resolver.
fn non_empty<T: Send + 'static>(
    ips: Vec<IpAddr>,
    pick: fn(IpAddr) -> Option<T>,
) -> Result<BoxIter<T>, DnsError> {
    let picked: Vec<T> = ips.into_iter().filter_map(pick).collect();
    if picked.is_empty() {
        return Err(e!(DnsError::NoResponse));
    }
    Ok(Box::new(picked.into_iter()))
}

impl Resolver for SystemResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        Box::pin(async move {
            non_empty(Self::lookup(host).await?, |ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        Box::pin(async move {
            non_empty(Self::lookup(host).await?, |ip| match ip {
                IpAddr::V6(v6) => Some(v6),
                IpAddr::V4(_) => None,
            })
        })
    }

    fn lookup_txt(&self, _host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        Box::pin(async { Err(e!(DnsError::NoResponse)) })
    }

    // The OS owns any caching, and re-reads its config on network changes.
    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(*self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_localhost_through_the_os() {
        let v4: Vec<Ipv4Addr> = SystemResolver
            .lookup_ipv4("localhost".into())
            .await
            .expect("localhost resolves")
            .collect();
        assert!(v4.contains(&Ipv4Addr::LOCALHOST), "got {v4:?}");
    }

    #[tokio::test]
    async fn txt_lookups_report_no_response() {
        let res = SystemResolver.lookup_txt("example.com".into()).await;
        assert!(matches!(res, Err(DnsError::NoResponse { .. })));
    }
}
