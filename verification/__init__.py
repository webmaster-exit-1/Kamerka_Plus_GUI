"""
verification – Tiered intelligence-gathering and cost-control pipeline.

Modules
-------
internet_db         Free InternetDB look-up (no API key) for basic port/tag
                    data before spending Shodan credits.
naabu_scanner       Thin wrapper around the FOSS Naabu port-scanner; confirms
                    that a target is *currently alive* before 3-D rendering.
shodan_analytics    Count-before-commit helper: calls shodan.count() /
                    shodan.stats() and produces a "Credit Cost vs Result
                    Density" report so the operator can decide whether to
                    proceed.  Also handles last-scanned deduplication via the
                    Device.last_scanned SQLite field.
honeypot_filter     Detects and excludes high-entropy clusters (≥ 500 identical
                    banners inside a /24 block) that almost certainly represent
                    honeypots or hosting-provider noise.
"""
