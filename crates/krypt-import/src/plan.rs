//! Sorting candidates into services and leaving out what the vault already holds.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use krypt_core::model::{DomainRule, Item, ItemData, Service};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::site::{host_of, site_of};
use crate::{Candidate, Parsed};

/// What an import is going to write.
#[derive(Debug, Default)]
pub struct Plan {
    /// Services the vault does not have yet.
    pub new_services: Vec<Service>,
    /// Entries to write, each pointing at an existing service, a new one or none.
    pub items: Vec<Item>,
    /// Names of existing services that receive entries.
    pub existing_services: Vec<String>,
    /// Entries left out because the vault or the file itself already has them.
    pub duplicates: usize,
    /// Entries the file had that Krypt cannot keep.
    pub skipped: usize,
}

/// Sorts `parsed` into the vault that holds `services` and `items`.
///
/// An entry with a web address goes to the service of its site (the registrable domain): an
/// existing one, found by domain or by name, or a new one named after the entries. A login is a
/// duplicate when its service, username, email and password match one already there; any other
/// entry when its service, label and content match.
pub fn plan(parsed: Parsed, services: &[Service], items: &[Item]) -> Plan {
    let names = preferred_names(&parsed.candidates);
    let mut plan = Plan {
        skipped: parsed.skipped,
        ..Plan::default()
    };
    let mut index = ServiceIndex::new(services);
    let mut seen: HashSet<[u8; 32]> = items.iter().map(fingerprint).collect();
    let mut ids: HashSet<Uuid> = items.iter().map(|item| item.id).collect();
    let mut receiving = BTreeSet::new();

    for Candidate {
        name,
        url,
        service,
        mut item,
    } in parsed.candidates
    {
        let web = url
            .as_deref()
            .and_then(|url| host_of(url).map(|host| (url, host)));
        let target = match (service, web) {
            (Some(template), _) => Some(index.adopt(template, &mut plan.new_services)),
            (None, Some((url, host))) => {
                let site = site_of(&host);
                let new_name = names
                    .get(&site)
                    .cloned()
                    .unwrap_or_else(|| display_name(&site));
                let (id, covers_site) = index.for_site(&site, new_name, &mut plan.new_services);
                // The exact address stays with the login when it says more than the service.
                let specific = host != site && host != format!("www.{site}");
                if let ItemData::Login(login) = &mut item.data
                    && (specific || !covers_site)
                    && !login.urls.iter().any(|known| known == url)
                {
                    login.urls.insert(0, url.to_owned());
                }
                Some(id)
            }
            (None, None) => None,
        };

        let mut receiver = None;
        match target {
            Some(id) => {
                item.service_id = Some(id);
                let (service_name, is_new) = index.describe(id);
                if item.label.is_empty()
                    && let Some(name) = name.filter(|name| {
                        !host_like(name) && !name.eq_ignore_ascii_case(&service_name)
                    })
                {
                    item.label = name;
                }
                if !is_new {
                    receiver = Some(service_name);
                }
            }
            None => {
                item.service_id = None;
                if item.label.is_empty() {
                    item.label = name.unwrap_or_default();
                }
            }
        }

        if !seen.insert(fingerprint(&item)) {
            plan.duplicates += 1;
            continue;
        }
        while !ids.insert(item.id) {
            item.id = Uuid::new_v4();
        }
        receiving.extend(receiver);
        plan.items.push(item);
    }

    plan.existing_services = receiving.into_iter().collect();
    plan
}

struct ServiceIndex {
    /// Name of every known service, and whether this import creates it.
    known: HashMap<Uuid, (String, bool)>,
    by_site: HashMap<String, Uuid>,
    by_name: HashMap<String, Uuid>,
}

impl ServiceIndex {
    fn new(services: &[Service]) -> Self {
        let mut index = Self {
            known: HashMap::new(),
            by_site: HashMap::new(),
            by_name: HashMap::new(),
        };
        for service in services {
            index.add(service, false);
        }
        index
    }

    fn add(&mut self, service: &Service, new: bool) {
        self.known.insert(service.id, (service.name.clone(), new));
        for domain in &service.domains {
            let host = domain.host.split(':').next().unwrap_or_default();
            self.by_site.entry(site_of(host)).or_insert(service.id);
        }
        self.by_name
            .entry(service.name.to_lowercase())
            .or_insert(service.id);
    }

    fn describe(&self, id: Uuid) -> (String, bool) {
        self.known.get(&id).cloned().unwrap_or_default()
    }

    /// The service for an entry of a Krypt export: the same service if the vault has it, one
    /// for the same site or with the same name, or else the exported service itself.
    fn adopt(&mut self, template: Service, new_services: &mut Vec<Service>) -> Uuid {
        if self.known.contains_key(&template.id) {
            return template.id;
        }
        let site = template
            .domains
            .first()
            .map(|domain| site_of(domain.host.split(':').next().unwrap_or_default()));
        let found = site
            .and_then(|site| self.by_site.get(&site).copied())
            .or_else(|| self.by_name.get(&template.name.to_lowercase()).copied());
        if let Some(id) = found {
            return id;
        }
        self.add(&template, true);
        let id = template.id;
        new_services.push(template);
        id
    }

    /// The service for a site: found by domain or by name, or created. The flag says whether
    /// the service's domains cover the site.
    fn for_site(
        &mut self,
        site: &str,
        name: String,
        new_services: &mut Vec<Service>,
    ) -> (Uuid, bool) {
        if let Some(&id) = self.by_site.get(site) {
            return (id, true);
        }
        if let Some(&id) = self.by_name.get(&name.to_lowercase()) {
            // A service this import creates can simply take the site as well.
            if let Some(service) = new_services.iter_mut().find(|service| service.id == id) {
                service.domains.push(DomainRule::new(site));
                self.by_site.insert(site.to_owned(), id);
                return (id, true);
            }
            return (id, false);
        }
        let mut service = Service::new(name);
        service.domains = vec![DomainRule::new(site)];
        self.add(&service, true);
        let id = service.id;
        new_services.push(service);
        (id, true)
    }
}

/// The name of each site's new service: the most common entry name that is more than an
/// address, the shorter one on a tie.
fn preferred_names(candidates: &[Candidate]) -> HashMap<String, String> {
    let mut votes: HashMap<String, Vec<(String, usize)>> = HashMap::new();
    for candidate in candidates.iter().filter(|c| c.service.is_none()) {
        let (Some(url), Some(name)) = (&candidate.url, &candidate.name) else {
            continue;
        };
        let Some(host) = host_of(url) else {
            continue;
        };
        if host_like(name) {
            continue;
        }
        let tally = votes.entry(site_of(&host)).or_default();
        match tally
            .iter_mut()
            .find(|(known, _)| known.eq_ignore_ascii_case(name))
        {
            Some((_, count)) => *count += 1,
            None => tally.push((name.clone(), 1)),
        }
    }
    votes
        .into_iter()
        .filter_map(|(site, tally)| {
            tally
                .into_iter()
                .max_by(|a, b| {
                    a.1.cmp(&b.1)
                        .then_with(|| b.0.chars().count().cmp(&a.0.chars().count()))
                })
                .map(|(name, _)| (site, name))
        })
        .collect()
}

/// `github.com` becomes "Github". IP addresses and hosts without a dot stay as they are.
fn display_name(site: &str) -> String {
    if site.parse::<IpAddr>().is_ok() || !site.contains('.') {
        return site.to_owned();
    }
    let label = site.split('.').next().unwrap_or(site);
    let mut chars = label.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => site.to_owned(),
    }
}

/// Names like `github.com` or `https://github.com/login` add nothing a service name would.
fn host_like(name: &str) -> bool {
    !name.contains(char::is_whitespace) && name.contains('.') && host_of(name).is_some()
}

/// Identifies an entry by what makes it the same entry, without keeping its secrets around.
fn fingerprint(item: &Item) -> [u8; 32] {
    let mut hash = Sha256::new();
    let mut part = |text: &str| {
        hash.update((text.len() as u64).to_le_bytes());
        hash.update(text.as_bytes());
    };
    part(&item.service_id.map(|id| id.to_string()).unwrap_or_default());
    match &item.data {
        ItemData::Login(login) => {
            part("login");
            part(
                &login
                    .username
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .to_lowercase(),
            );
            part(
                &login
                    .email
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .to_lowercase(),
            );
            part(login.password.expose());
        }
        data => {
            part(&item.label);
            part(&Zeroizing::new(
                serde_json::to_string(data).unwrap_or_default(),
            ));
        }
    }
    let digest = hash.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}
