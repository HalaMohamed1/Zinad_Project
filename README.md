# 🛡️ ZINAD — Integrated Threat Intelligence & Phishing Detection Tool

---

## 📖 Overview
**ZINAD** is an integrated **Threat Intelligence (TI)** and **Phishing Detection** system that combines real-time indicator collection, enrichment, campaign correlation, and phishing classification.  
The tool detects and analyzes malicious URLs or emails using data from open threat feeds, WHOIS, SSL, GeoIP, and brand similarity features.  

It provides a **Streamlit-based dashboard** for real-time visualization and interactive URL risk analysis.

---

## 🎯 Objectives
- Collect and normalize phishing-related indicators from open-source threat intelligence feeds.  
- Enrich indicators with contextual information (WHOIS, SSL, GeoIP, ASN reputation, etc.).  
- Correlate related indicators into coordinated phishing campaigns.  
- Detect and classify phishing URLs using heuristic and ML-based scoring.  
- Visualize results in an interactive dashboard.

---

## ⚙️ System Workflow

### 1. **Data Collection (Threat Intelligence Layer)**
- Pulls data from **OpenPhish**, **PhishTank**, **URLhaus**, and **Spamhaus DBL**.
- Normalizes indicators (URLs, IPs, domains) into a unified database schema.

### 2. **Enrichment & Scoring**
- Adds contextual metadata:
  - WHOIS information  
  - Domain age  
  - SSL/TLS details  
  - GeoIP location  
  - ASN reputation  
  - Brand similarity (Levenshtein/Fuzzy matching)
- Computes a **risk score (0–100)** per indicator.

### 3. **Campaign Correlation**
- Groups indicators with similar registrars, ASNs, or certificate fingerprints into phishing “campaigns”.

### 4. **Detection Module**
- Ingests new URLs or emails.  
- Extracts indicators and retrieves contextual threat data.  
- Calculates combined score (TI + heuristic/ML).  
- Classifies inputs as **phishing** or **legitimate**.

### 5. **Visualization & Reporting**
- Displays:
  - Trending phishing campaigns  
  - Top targeted brands  
  - Geographic distribution of malicious hosts  
  - Real-time detection outcomes  
- Exports data in **CSV** or **STIX** formats.

---

## 🧰 Tech Stack
| Component | Technology |
|------------|-------------|
| **Language** | Python |
| **Database** | SQLite |
| **Dashboard** | Streamlit + Plotly |
| **Libraries** | pandas, dnspython, geoip2, python-whois, scikit-learn, fuzzywuzzy |
| **Deployment** | Pyngrok (for public access) |

---

## 🚀 Installation & Usage

### 1. Clone the repository
```bash
git clone https://https://github.com/HalaMohamed1/Zinad_Project
```

### 2. Run the Streamlit dashboard
```bash
streamlit run URL_Detection.ipynb
```
*(You may first convert it to a `.py` file if needed)*

### 3. Use the interface
- Enter a URL to test.
- View extracted features, risk score, and classification result.
- Explore the campaigns and detection logs in real-time.

---

## 🧠 Scoring Algorithm

The final phishing risk score is a weighted combination of:
- **Domain age** (new domains are riskier)  
- **SSL/TLS validity**  
- **Reputation in CTI feeds**  
- **Brand similarity** (e.g., `faceb00k.com` ≈ `facebook.com`)  
- **ASN reputation & GeoIP**  


## 📚 References
- [OpenPhish](https://openphish.com/)  
- [PhishTank API](https://www.phishtank.com/developer_info.php)  
- [URLhaus](https://urlhaus.abuse.ch/)  
- [MITRE ATT&CK T1566](https://attack.mitre.org/techniques/T1566/)  
- [Nazario Phishing Corpus](http://monkey.org/~jose/wiki/doku.php?id=phishingcorpus)  
- [Enron Email Dataset](https://www.cs.cmu.edu/~enron/)

---
