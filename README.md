# fakirtools

Tools for Large-Scale Newly Registered Domain Collection, WHOIS/DNS Enrichment, and Clustering

This repository contains two Python scripts designed to work together:

1. **domain_analyze.py** – Fetches newly-seen domains, performs DNS + WHOIS enrichment, and saves the results into a structured CSV file.
2. **cluster.py** – Clusters domains based on shared WHOIS, DNS, or IP-related attributes from the generated CSV/TXT dataset.

Both tools are optimized for low-RAM servers, incremental processing, and scalable handling of thousands of domains.

---

## 📌 Files

### **domain_analyze.py**

A lightweight but robust domain analysis pipeline that:

* Fetches today’s newly-observed domains from **ISC SANS API**
* Performs:

  * WHOIS lookups
  * DNS resolution (A, AAAA, MX, NS, TXT, SOA, DMARC)
  * IP geolocation (ASN, Organization, Country, City, Lat/Lon)
* Includes:

  * Automatic rate limiting
  * Persistent progress tracking (resume on restart)
  * Graceful shutdown with SIGINT/SIGTERM handling
  * Incremental CSV writing (no memory buildup)
  * Duplicate-run detection via MD5 checksums

Results are saved in:

```
domain_analysis.csv
progress.json
domains_hash.txt
```

---

### **cluster.py**

A high-performance clustering tool for enriched domain datasets.

Features:

* Cluster by **any combination of WHOIS / DNS / IP fields**
* Filter clusters by minimum size
* Sort clusters by number of domains
* Auto-formatted output report
* Statistical summary (largest cluster, avg size, etc.)

Example fields available for clustering:

```
domain, registrarName, nameServers, registrant_organization,
ip_asn, ip_org, ip_country, status, MX_values, NS_values, ...
```

---

## 🚀 Usage

### 1. **Run domain analysis**

Fetch domains → perform WHOIS/DNS enrichment → save CSV.

```
python3 domain_analyze.py
```

Optional arguments:

```
--limit N       Process only first N domains
--skip-whois    Skip WHOIS lookups (significantly faster)
```

Output example:

* `domain_analysis.csv` – structured dataset usable by cluster.py
* Progress automatically saved to `progress.json`
* Script automatically resumes where it left off

---

### 2. **Run clustering**

Basic clustering by name servers and registrant organization:

```
python3 cluster_domains.py domain_analysis.csv clusters.txt -f nameServers registrant_organization
```

Cluster using multiple fields with a minimum size of 5:

```
python3 cluster_domains.py domain_analysis.csv clusters.txt \
    -f nameServers registrant_organization ip_asn -m 5
```

Cluster by registrar and IP org:

```
python3 cluster_domains.py domain_analysis.csv clusters.txt \
    -f registrarName ip_org ip_country
```

Output example structure:

```
================================================================================
DOMAIN CLUSTERING RESULTS
Clustered by: nameServers, registrant_organization
Total clusters: 42
================================================================================

===============================================================================
CLUSTER #1 - 18 domains
===============================================================================
  nameServers: ns1.example.com|ns2.example.com
  registrant_organization: Example Corp

Domains in this cluster:
  - example.com
  - example.net
  - example.org
  ...
```

---

## 🧰 Dependencies

Install required modules:

```
pip install python-whois dnspython requests
```

Recommended (for stability):

```
pip install whois
```

## 📄 License

MIT License – free for research, security investigations, and commercial use.
