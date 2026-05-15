"""
Curated list of ~50 RSS feeds for cybersecurity, ICS/SCADA, geopolitics,
and infrastructure intelligence.

Used by the seed_feeds management command to populate FeedSource records.
"""

SEED_FEEDS = [
    # ── Cybersecurity ──────────────────────────────────────────────────
    {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "category": "cyber",
    },
    {
        "name": "CISA ICS Advisories",
        "url": "https://www.cisa.gov/uscert/ics/advisories",
        "category": "ics",
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "cyber",
    },
    {
        "name": "Schneier on Security",
        "url": "https://www.schneier.com/feed/atom/",
        "category": "cyber",
    },
    {
        "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed_full.xml",
        "category": "cyber",
    },
    {
        "name": "Threatpost",
        "url": "https://threatpost.com/feed/",
        "category": "cyber",
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "category": "cyber",
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "category": "cyber",
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss/all.xml",
        "category": "cyber",
    },
    {
        "name": "SecurityWeek",
        "url": "https://feeds.feedburner.com/Securityweek",
        "category": "cyber",
    },
    {
        "name": "NVD Recent CVEs",
        "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml",
        "category": "cyber",
    },
    {
        "name": "Exploit-DB",
        "url": "https://www.exploit-db.com/rss.xml",
        "category": "cyber",
    },
    {
        "name": "Google Project Zero",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "category": "cyber",
    },
    # ── ICS / SCADA ────────────────────────────────────────────────────
    {
        "name": "ICS-CERT Advisories (CISA)",
        "url": "https://www.cisa.gov/uscert/ics/advisories",
        "category": "ics",
    },
    {
        "name": "Dragos ICS Blog",
        "url": "https://www.dragos.com/feed/",
        "category": "ics",
    },
    {
        "name": "Claroty Blog",
        "url": "https://claroty.com/team82/research/feed",
        "category": "ics",
    },
    {
        "name": "Nozomi Networks Blog",
        "url": "https://www.nozominetworks.com/blog/feed/",
        "category": "ics",
    },
    {
        "name": "SCADA Strangelove",
        "url": "https://scada.sl/feed",
        "category": "ics",
    },
    # ── Geopolitics ───────────────────────────────────────────────────
    {
        "name": "ACLED Conflict Data",
        "url": "https://acleddata.com/feed/",
        "category": "geo",
    },
    {
        "name": "ReliefWeb Updates",
        "url": "https://reliefweb.int/updates/rss.xml",
        "category": "geo",
    },
    {
        "name": "Bellingcat",
        "url": "https://www.bellingcat.com/feed/",
        "category": "geo",
    },
    {
        "name": "Foreign Policy",
        "url": "https://foreignpolicy.com/feed/",
        "category": "geo",
    },
    {
        "name": "Chatham House",
        "url": "https://www.chathamhouse.org/rss.xml",
        "category": "geo",
    },
    # ── Infrastructure ────────────────────────────────────────────────
    {
        "name": "CAIDA Internet Outages",
        "url": "https://www.caida.org/catalog/datasets/outages/feed",
        "category": "infra",
    },
    {
        "name": "Internet Society Blog",
        "url": "https://www.internetsociety.org/feed/",
        "category": "infra",
    },
    {
        "name": "RIPE NCC Blog",
        "url": "https://labs.ripe.net/atom.xml",
        "category": "infra",
    },
    {
        "name": "USGS Earthquake Alerts",
        "url": "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/significant_week.atom",
        "category": "infra",
    },
    {
        "name": "Global Disaster Alert and Coordination System",
        "url": "https://gdacs.org/xml/rss.xml",
        "category": "infra",
    },
    # ── Threat Intelligence ───────────────────────────────────────────
    {
        "name": "AlienVault OTX",
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10&modified_since=2020-01-01T00:00:00",
        "category": "cyber",
    },
    {
        "name": "Recorded Future Blog",
        "url": "https://www.recordedfuture.com/feed/",
        "category": "cyber",
    },
    {
        "name": "Mandiant Blog",
        "url": "https://www.mandiant.com/resources/blog/rss.xml",
        "category": "cyber",
    },
    {
        "name": "Rapid7 Blog",
        "url": "https://blog.rapid7.com/rss/",
        "category": "cyber",
    },
    {
        "name": "Qualys Security Blog",
        "url": "https://blog.qualys.com/feed",
        "category": "cyber",
    },
    {
        "name": "Tenable Blog",
        "url": "https://www.tenable.com/blog/feed",
        "category": "cyber",
    },
    {
        "name": "Securelist (Kaspersky)",
        "url": "https://securelist.com/feed/",
        "category": "cyber",
    },
    {
        "name": "WeLiveSecurity (ESET)",
        "url": "https://www.welivesecurity.com/feed/",
        "category": "cyber",
    },
    {
        "name": "Cisco Talos Blog",
        "url": "https://blog.talosintelligence.com/feeds/posts/default",
        "category": "cyber",
    },
    {
        "name": "Unit 42 (Palo Alto)",
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "category": "cyber",
    },
    {
        "name": "Microsoft Security Blog",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "category": "cyber",
    },
    {
        "name": "Google Security Blog",
        "url": "https://security.googleblog.com/feeds/posts/default",
        "category": "cyber",
    },
    {
        "name": "AWS Security Blog",
        "url": "https://aws.amazon.com/blogs/security/feed/",
        "category": "cyber",
    },
    {
        "name": "National Cyber Security Centre (UK)",
        "url": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        "category": "cyber",
    },
    {
        "name": "ENISA News",
        "url": "https://www.enisa.europa.eu/news/enisa-news/RSS",
        "category": "cyber",
    },
]
