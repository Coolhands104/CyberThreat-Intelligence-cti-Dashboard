 Cyber Threat Intelligence (CTI) Dashboard
 
📌 Overview

The Cyber Threat Intelligence (CTI) Dashboard is a Python + Streamlit application that allows users to quickly analyze IPs, domains, URLs, and file hashes using multiple public threat intelligence sources.
This project integrates with:
●	VirusTotal
●	AbuseIPDB
●	AlienVault OTX
The dashboard provides a risk score (Low/Medium/High) along with both a summary view and raw JSON evidence. Users can also download structured reports for further analysis.

✨ Features

●	🔍 Lookup support for IPs, Domains, URLs, and Hashes
●	📊 Risk scoring based on multi-source intelligence
●	📑 Tabbed results: Summary table + Raw JSON evidence
●	💾 Export JSON report for offline use
●	⚡ Cached queries for faster lookups

🛠️ Tools & Technologies

●	Python 3.11+
●	Streamlit – Interactive UI
●	Requests – API communication
●	Pandas – Data summarization
●	APIs – VirusTotal, AbuseIPDB, AlienVault OTX

🚀 Installation

Clone the repository and install dependencies:
git clone [https://github.com/your-username/cti-dashboard.git](https://github.com/your-username/cti-dashboard.git)
cd cti-dashboard
pip install -r requirements.txt

▶️ Usage

Run the application:

streamlit run app.py

Open the link in your browser (default: http://localhost:8501).
1.	Enter an IP, Domain, URL, or File Hash in the search box.
2.	Click Lookup to fetch intelligence results.
3.	View results in two tabs:
  ○	Summary → Clean overview of risk score and details.
  ○	Raw Evidence → Full JSON data from APIs.
4.	Click ⬇️ Download JSON Report to save the results.
