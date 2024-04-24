# SolarWinds Sunburst Case Study

# Contents

1. Introduction
2. Timeline
3. Closer Analysis
4. Mitigation Plan
5. MITRE ATT&CKs
6. CVEs
7. Sources

# 1. Introduction

SolarWinds is a global leader in IT management software. It offers robust and affordable solutions that allow organizations of all types, sizes, and complexities to monitor and manage their IT services, infrastructures, and applications. This includes both on-premises and cloud-based environments, as well as hybrid models.

The SolarWinds Orion Platform is a powerful tool provided by SolarWinds. It enables organizations to manage their IT services, infrastructures, and applications effectively. This platform is versatile and supports various environments, including on-premises, cloud, and hybrid models. The Orion Platform is written in multiple languages, such as Go, Java, C++, Python, and primarily C#. It provides a comprehensive suite of tools for IT administrators to manage network performance, system performance, database performance, IT security, and more.

The SolarWinds Sunburst Case Study discusses a sophisticated cyberattack that occurred in December 2020, where threat actors inserted malicious code into the software updates of the SolarWinds Orion Platform. This allowed them to compromise numerous organizations worldwide. The attack is considered one of the most significant cyber espionage events due to its scale and sophistication. The document details the timeline of the attack, provides a closer analysis of how the attack was carried out, discusses mitigation strategies, highlights relevant MITRE ATT&CKs, and lists CVEs related to the attack. It also includes additional resources for further reading.

# 2. Timeline:

<img src="SolarWinds Sunburst Case Study Folder Pics/SSCS 1.png">
*Picture Credited To - [SolarWinds attack changing nature of cybersecurity for ICSs | Industrial Cybersecurity Pulse | Industrial Cybersecurity Pulse](https://www.industrialcybersecuritypulse.com/it-ot/changing-winds-of-cybersecurity-for-icss/)

# 3. Closer Analysis:

## Sunburst Attack Overview:

<img src="SolarWinds Sunburst Case Study Folder Pics/SSCS 2.png">
*Picture Credited To - [Analyzing Solorigate, the compromised DLL file that started a sophisticated cyberattack, and how Microsoft Defender helps protect customers | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/)

## Code Analysis:

<img src="SolarWinds Sunburst Case Study Folder Pics/SSCS 3.png">
*Picture Credited To - [Analyzing Solorigate, the compromised DLL file that started a sophisticated cyberattack, and how Microsoft Defender helps protect customers | Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/)

In the SolarWinds Orion Platform, the attackers strategically injected malicious code into the *SolarWinds.Orion.Core.BusinessLayer.dll* code library. They carefully selected a method within this DLL component that is regularly invoked to embed their code, ensuring its consistent execution and persistence. The method named *RefreshInternal* met these criteria and was chosen for this purpose.

The backdoor's operations are entirely contained within the *OrionImprovementBusinessLayer* class, 3 which consists of 13 subclasses and 16 methods. Its name is designed to blend in with legitimate code. The threat actors purposefully avoided using obvious terms such as "backdoor" or "keylogger", choosing more neutral language instead. The code within this DLL appears standard at first glance, potentially explaining why the inserted malicious code went undetected for several months, especially if updates to this DLL were infrequent. To provide a basic level of concealment, the strings within the backdoor are compressed, Base64 encoded, or replaced by their hashes.

The SolarWinds Orion Platform is written in Go, Java, C++, Python, and mainly in C# which the DLL was written in.

# 4. Mitigation Plan:

### **Step 1: User Training and Awareness**

- **Security Awareness Training:** Educate employees about the risks associated with supply chain attacks like the SolarWinds incident. Explain how attackers can exploit trusted software vendors to gain unauthorized access to organizational networks.

### **Step 2: Access Control and Authentication**

- **Access Control - Network Segmentation:** Use network segmentation to isolate critical systems and limit lateral movement in the event of a security breach. This helps contain the impact of a compromised account.

- **Authentication - Strong Password Policies:** Implement and enforce strong password policies, including requirements for complex passwords and regular password changes. Consider the use of passphrase policies for stronger user authentication.

### **Step 3: Network Security**

- **Supply Chain Security:** Organizations should prioritize the security of their software supply chain. Regularly assess and validate the security measures implemented by third-party vendors and providers. Implement strict controls for software updates and patches, ensuring that they undergo thorough security reviews before deployment.

### **Step 4: Endpoint Protection**

- **Advanced Endpoint Protection:** Invest in advanced endpoint protection solutions that go beyond traditional antivirus tools. Utilize technologies like behavioral analysis, machine learning, and threat intelligence to detect and respond to sophisticated threats.

### **Step 5: Security Monitoring, Incident Response, Business Continuity Plan and Disaster Recovery Plan**

- **Security Monitoring - Continuous Monitoring:** Implement continuous monitoring solutions to detect and respond to security incidents in real-time. This includes monitoring network traffic, logs, and system activities for anomalous behavior.

- **Incident Response - Incident Response Planning:** Develop and regularly update comprehensive incident response plans. These plans should outline the steps to be taken in the event of a security incident, including communication protocols, containment procedures, and recovery processes.

- **Business Continuity Plan (BCP) - Risk Assessment:** Conduct regular risk assessments to identify potential threats to business operations. Understand the dependencies on critical systems and services, including those provided by third-party vendors.

- **Disaster Recovery Plan (DRP) - Data Backups and Restoration:** Regularly back up critical data and test the restoration process to ensure data integrity and availability during recovery efforts. Consider maintaining both on-site and off-site backups.

### **Step 6: Compliance and Documentation**

- **Compliance - Regulatory Compliance:** Stay abreast of relevant industry and regulatory standards for cybersecurity. Understand the specific compliance requirements that apply to your organization based on its industry, location, and the nature of the data it handles.

- **Documentation - Security Policies and Procedures:** Regularly review and update security policies and procedures. Ensure that these documents are comprehensive, clearly written, and accessible to all relevant stakeholders. They should cover aspects such as access controls, data protection, and incident response.

### **Step 7: Accurate Inventory, Vulnerability Assessment, and System Hardening**

- **Accurate Inventory - Continuous Monitoring:** Implement continuous monitoring mechanisms to detect and track changes in the IT environment. This includes additions, modifications, or removals of assets. Regularly reconcile the inventory with the actual state of the network.

- **Vulnerability Assessment - Regular Vulnerability Scanning:** Conduct regular vulnerability assessments using automated scanning tools to identify and prioritize vulnerabilities in the organization's systems. Perform both internal and external scans to cover all potential attack vectors.

- **System Hardening - Baseline Security Configurations:** Define and enforce baseline security configurations for all systems. Establish security standards for operating systems, applications, and network devices, and ensure that these configurations are consistently applied across the organization.

### **Step 8: Patch Management**

- **Test Patches Before Deployment:** Before deploying patches to production environments, conduct thorough testing in a controlled environment. Verify that patches do not introduce compatibility issues or negatively impact system performance.

### **Step 9: Continuous Improvement**

- **Regular Testing:** Regular security assessments, penetration testing, and vulnerability scanning can identify and address weaknesses in your defenses proactively (mitigating potential exploitation of all CVEs by identifying and fixing vulnerabilities before they are exploited).
- **Stay Informed:** Staying informed about emerging threats and vulnerabilities through threat intelligence sources helps you stay ahead of potential risks and take appropriate mitigation actions.

# 5. MITRE ATT&CKs

1. [**Supply Chain Compromise (T1195.001)**](https://attack.mitre.org/techniques/T1195/001/): Attackers inserted malicious code into a SolarWinds Orion software update, allowing them to distribute the malware to numerous organizations.

1. [**Dynamic Resolution: Domain Generation Algorithms (DGAs) (T1568.002)**](https://attack.mitre.org/techniques/T1568/002/): Attackers used DGAs to generate a parent domain and randomly generated subdomains for command-and-control communications, evading detection and making it challenging for defenders to block or take over the C2 channel.

1. [**Execution Guardrails: Environmental Keying (T1480.001)**](https://attack.mitre.org/techniques/T1480/001/): Attackers encrypted payloads using the Data Protection API (DPAPI) and derived an RC5 key from the infected system's volume serial number, making sandbox detection, anti-virus detection, and reverse engineering difficult.

More MITRE ATT&CKs related to Sunburst - [SUNBURST, Software S0559 | MITRE ATT&CK®](https://attack.mitre.org/software/S0559/)

# 6. CVEs:

[**CVE-2020-10148**](https://nvd.nist.gov/vuln/detail/CVE-2020-10148): Vulnerability in the SolarWinds Orion software that allows for an authentication bypass, potentially enabling unauthenticated API commands and leading to a compromise of the SolarWinds instance.

# 7. Sources:

1. Microsoft Threat Intelligence. “Analyzing Solorigate, the compromised DLL file that started a sophisticated cyberattack, and how Microsoft Defender helps protect customers” *Microsoft,* Dec 18, 2020. [https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/](https://www.microsoft.com/en-us/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/)

1. Vavra, Chris. “SolarWinds attack changing nature of cybersecurity for ICSs” *Industrial Cybersecurity Pulse,* Feb 9, 2021. [https://www.industrialcybersecuritypulse.com/it-ot/changing-winds-of-cybersecurity-for-icss/](https://www.industrialcybersecuritypulse.com/it-ot/changing-winds-of-cybersecurity-for-icss/)

1. Jagnow, Dan. “The SolarWinds Platform and .NET: New Horizons With .NET Core” *Orange Matter,* July 12, 2022. [https://orangematter.solarwinds.com/2022/07/12/solarwinds-platform-new-horizons-with-net-core/](https://orangematter.solarwinds.com/2022/07/12/solarwinds-platform-new-horizons-with-net-core/)
