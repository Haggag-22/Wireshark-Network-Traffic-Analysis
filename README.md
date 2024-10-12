# Trickbot Malware Network Traffic Analysis


### Background
`CatBOMBER` is a malware strain delivered via phishing emails, known for exfiltrating sensitive information and maintaining persistent access to compromised systems. Analyzing its network behavior is vital for improving detection and response strategies.

You can access the PCAP file directly in this repository: [trickbot_malware.pcap](https://github.com/Haggag-22/Wireshark-Network-Traffic-Analysis/blob/main/trickbot_malware.pcap)
### Scope
1. **Traffic Analysis:** Identify patterns and malicious activities within the captured traffic.
2. **Malware Behavior:** Determine how `CatBOMBER` infiltrates systems and spreads.
3. **Indicators of Compromise (IOCs):** IOCs such as file hashes, IP addresses, and domains.
4. **Remediation Recommendations:** Provide actionable insights for mitigating impacts.

### Methodology
- **Tools Used:** `Wireshark` for PCAP analysis, `VirusTotal` for IOC assessment, `WHOIS lookup` for domain analysis, and `VirtualBox` for creating a controlled environment.
- **Process:** Import the PCAP into `Wireshark` for detailed analysis, extract and analyze IOCs with `VirusTotal`, and document results and recommendations in a comprehensive report.

