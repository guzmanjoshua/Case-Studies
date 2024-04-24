# WannaCry Case Study

# Contents

1. Introduction
2. Timeline
3. Closer Analysis
4. Mitigation Plan
5. MITRE ATT&CKs
6. CVEs
7. Additional Facts
8. Sources

# 1. Introduction

WannaCry, also known as Wanna Decryptor, is a notorious ransomware worm that had a significant impact on a global scale in May 2017. The malware targeted computers running the Microsoft Windows operating system, encrypting data and demanding Bitcoin ransom payments.

WannaCry took advantage of an exploit named EternalBlue, believed to have been developed by the U.S. National Security Agency (NSA), which had been leaked by the hacker group "The Shadow Brokers" a few months before the attack.

This case study outlines the timeline of the WannaCry attack, provides a closer examination of how the malware and the EternalBlue exploit work, and discusses the ongoing risks and mitigations associated with this type of ransomware attack. Despite the activation of a kill-switch domain that curbed the initial outbreak, the threat of WannaCry and similar attacks persists due to new versions of the malware and the continued presence of unpatched systems.

Understanding the mechanics of these attacks and implementing robust security measures, including regular software updates, network segmentation, access control, continuous monitoring and incident response planning, are critical to preventing future infections and minimizing potential damage.

# 2. Timeline:

### Around 2012 - Creation of EternalBlue:

EternalBlue was developed by the NSA, which had spent years searching for potential vulnerabilities in Microsoft software.

 When it finally found a weakness in the SMBv1 protocol, the NSA developed its exploit as a way to take advantage of that vulnerability. 

Instead of alerting Microsoft to the risks its users faced, the NSA used EternalBlue to aid in antiterrorism and counterintelligence operations for half a decade.

### Around End of 2016 - 2017 - EternalBlue was Stolen:

The NSA discovered the EternalBlue exploit was stolen. NSA informed Microsoft of this exploit. 

### March 14, 2017 - Microsoft Patches EternalBlue:

Windows releases [Microsoft Security Bulletin MS17-010](https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010), which patches EternalBlue vulnerability [CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144) to the supported Windows Versions at the time. 

Windows XP, Windows Server 2003 and, Windows 8 which were unsupported at the time got the patch during the second release. 

### April 14, 2017 - EternalBlue Leaked:

The notorious hacking group, the Shadow Brokers leaked EternalBlue via a link on their Twitter Account.

### May 12, 2017 (7:44 UTC) - The WannaCry Attack Began:

The WannaCry ransomware worm was first sited in 7:44UTC and continue to attack, until 15:03 UTC. The attack spread to more than 200,000 computers in over 150 countries. Notable victims included FedEx, Honda, Nissan, and the UK's National Health Service (NHS), which was forced to divert some of its ambulances to alternate hospitals. These victims did not update their systems to patch the EternalBlue vulnerability CVE-2017-0144 which came out two months before this attack as shown above.

### May 12, 2017 (15:03 UTC) - WannaCry Attack Is Stopped:

A few hours later on the day of the attack, a security blogger and researcher named Marcus Hutchings began reverse-engineering the WannaCry source code. He discovered that WannaCry included an unusual function: before executing, it would query the domain iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com. This website did not exist, so he registered the domain. 

After Hutchins did so, copies of WannaCry continued to spread, but they stopped executing. Essentially, WannaCry turned itself off once it began getting a response from iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com.

### As of March 2021 - A New WannaCry:

The version of WannaCry that was released into the world in 2017 no longer functions due to the off-switch domain. However, WannaCry attacks continue to occur since there are new versions of WannaCry which have removed the kill switch feature present in the original version. The solutions to mitigate this malware still works for newer version, but people are still persisted into installing the latest patches or implementing necessary actions.

# 3. Closer Analysis:

## Why People Don’t Like Updating:

To stay safe from WannaCry, all people needed to do was update their software. However, many often don't due to various reasons. In 2016, researchers from the University of Edinburgh and Indiana University surveyed 307 people about their experiences with software updates.

Nearly half mentioned their frustration with updating software, while only 21 percent shared a positive experience. The researchers emphasized one participant's observation that Windows updates, which are released frequently and can take a long time to install, often disrupt their workflow. As a result, this participant, along with many others, avoided installing updates for as long as they could.

Patching is a significant challenge for IT managers. The WannaCry incident and its variants have shown that staying updated with patches is not common. Only 31% of companies using Windows have the latest operating system (OS), while 60% are using Windows versions that no longer receive regular support.

Running an outdated OS triples the risk of a cyber-attack. This fact alone is worrisome. However, for small to medium enterprises (SMEs), the situation is even more daunting. A recent study by Juniper found that SMEs typically use older software and tend to allocate less than $4,000 to cybersecurity, making them more susceptible to cyber-attacks.

Many companies find it challenging to keep up with patching due to factors like resource and training shortages, and the sheer volume of patches. Vulnerabilities in third-party applications can be overlooked, and manual or vendor-supplied patching processes may be inefficient. Moreover, some appliances can only be patched by the vendor, and outdated software might no longer be supported, leaving vulnerabilities unaddressed.

End-users can also resist patching due to the inconvenience of required restarts and system updates, as previously discussed. Much of this worry stems from the fear of causing operational issues, such as malfunctioning applications. However, in reality, the percentage of patches that actually cause operational issues is small.

The belief that current security measures are adequate can deter companies from prioritizing patching. Nevertheless, patch automation can help alleviate these concerns and ensure all software vulnerabilities are promptly addressed.

## How EternalBlue Worked:

The EternalBlue exploit works by taking advantage of SMBv1 vulnerabilities ****present in older versions of Microsoft operating systems. SMBv1 was first developed in early 1983 as a network communication protocol to enable shared access to files, printers, and ports. It was essentially a way for Windows machines to talk to one another and other devices for remote services.

This exploit dupes a Windows machine that has not been patched against the vulnerability into allowing illegitimate data packets into the legitimate network. These data packets can contain malware such as a trojan, ransomware, or similar dangerous program. In this case the data packets used was the WannaCry ransomware.

## How WannaCry Worked:

The WannaCry ransomware executable is fairly simple. It arrives on the infected computer in the form of a dropper*,* a self-contained program that extracts the other application components embedded within itself. These components are an application the encrypts and decrypts data, files containing encryption keys, a copy of TOR bowser which was used for command-and-control communications. 
The original WannaCry source code hasn’t been found or made available to researchers, although it’s easy enough for them to examine the binary’s execution. Once launched, WannaCry tries to access a hard-coded domain. If the ransomware can connect to that domain, it shuts down; if it can’t, it proceeds to search for and encrypt files in a slew of important formats, ranging from Microsoft Office files to MP3s and MKVs, leaving them inaccessible to the user. It then displays a ransom notice, demanding $300 Bitcoin. 
There are sources that say once the Bitcoin is paid, the victims will not receive the files and the amount of Bitcoin will increase.

## Why WannaCry have a Domain Off Switch:

While the WannaCry authors' motivations cannot be known for certain, it is theorized that this domain query function was included in WannaCry so that the ransomware could check if it was inside a sandbox. One way that malware could check if it is inside a sandbox is by sending a query to a fake domain. If it gets a "real" response (generated by the sandbox), it can assume it is in a sandbox and shut itself down so that the sandbox does not detect it as malicious.

However, if the malware sends its test query to a hard-coded domain, then it can be tricked into thinking it is always in a sandbox if someone registers the domain. This could be what happened with WannaCry: copies of WannaCry across the world were tricked into thinking they were inside a sandbox and shut themselves down.

Another possible explanation is that the copy of WannaCry that spread across the world was unfinished. The authors of WannaCry may have hard-coded that domain as a placeholder, intending to replace it with the address of their command-and-control (C&C) server before releasing the worm. Or they may have meant to register iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com themselves.

## Duplicating the WannaCry Attack:

### Recon Process

In the initial stage of this cyberattack, a threat actor could use different methods to identify systems susceptible to the EternalBlue vulnerability. Here are some techniques they might employ:

- **Scanning for Open Ports:** The threat actor could use port scanning tools like Nmap to identify systems with open ports, such as SMBv1 (Server Message Block) ports (e.g., port 445). By scanning a range of IP addresses, they can identify potential targets that have SMB services exposed to the internet.

The image below shows successful finding of EternalBlue vulnerability using nmap

<img src="WannaCry Case Study Folder Pics/WCS 1.png">

Cybernews screenshot

- **Exploit Frameworks:** There are well-known exploit frameworks like Metasploit that contain modules specifically designed to exploit the EternalBlue vulnerability. These frameworks provide a wide range of tools and exploits for attackers to leverage, including EternalBlue. By using such frameworks, the attacker can automate the process of identifying vulnerable systems and launching attacks.

The image below shows prebuilt EternalBlue exploits

<img src="WannaCry Case Study Folder Pics/WCS 2.png">

Cybernews screenshot

- **Shodan and Similar Tools:** Shodan is a search engine that scans and indexes internet-connected devices, including vulnerable systems. By using specific search queries, an attacker can identify systems that are potentially susceptible to EternalBlue. Similar tools or databases listing vulnerable systems can also aid in identifying targets.

It's important to note that discovering vulnerable systems is only the first step for threat actors. Once they identify a vulnerable system, they proceed to exploit the vulnerability, gain access, and then move laterally within the network to escalate privileges and achieve their objectives.

### Exploit Execution

Once the target system is identified, the attacker launches an exploit against the vulnerable system. One of the most popular exploitation tools is Metasploit Framework.

### What is Metasploit Framework?

The Metasploit Framework is a Ruby-based, modular penetration testing platform that enables you to write, test, and execute exploit code. The Metasploit Framework contains a suite of tools that you can use to test security vulnerabilities, enumerate networks, execute attacks, and evade detection. At its core, the Metasploit Framework is a collection of commonly used tools that provide a complete environment for penetration testing and exploit development.

Metasploit Framework has an EternalBlue exploit, which can be used directly to exploit vulnerable systems.

<img src="WannaCry Case Study Folder Pics/WCS 3.png">

Cybernews screenshot

The image below shows successful exploitation of the EternalBlue vulnerability

<img src="WannaCry Case Study Folder Pics/WCS 4.png">

Cybernews screenshot

### First Bug

EternalBlue takes advantage of three different bugs. The first is a mathematical error when the protocol tries to cast an OS/2 File Extended Attribute (FEA) list structure to an NT FEA structure in order to determine how much memory to allocate. A miscalculation creates an integer overflow that causes less memory to be allocated than expected, which in turns leads to a buffer overflow. With more data than expected being written, the extra data can overflow into adjacent memory space triggering the buffer overflow. 

### Second Bug

This is achieved due to the second bug, which results from a difference in the SMB protocol’s definition of two related sub commands: SMB_COM_TRANSACTION2 and SMB_COM_NT_TRANSACT.

Both have a _SECONDARY command that is used when there is too much data to include in a single packet. The crucial difference between TRANSACTION2 and NT_TRANSACT is that the latter calls for a data packet twice the size of the former. This is significant because an error in validation occurs if the client sends a crafted message using the NT_TRANSACT sub-command immediately before the TRANSACTION2 one.

While the protocol recognizes that two separate sub-commands have been received, it assigns the type and size of both packets and allocates memory accordingly based only on the type of the last one received. Since the last one is smaller, the first packet will occupy more space than it is allocated.

### Third Bug

Once the attackers achieve this initial overflow, they can take advantage of a third bug in SMBv1 which allows heap spraying, a technique which results in the allocation of a chunk of memory at a given address. From here, the attacker can write and execute shellcode to take control of the system.

Upon successfully compromising the initial system, the attacker begins their reconnaissance phase. They explore the network, scanning for other vulnerable systems or potential targets. Using tools like Nmap or Metasploit, the attacker identifies additional systems with unpatched vulnerabilities, possibly even finding weak or default credentials that grant further access.

<img src="WannaCry Case Study Folder Pics/WCS 5.png">

Cybernews screenshot

<img src="WannaCry Case Study Folder Pics/WCS 6.png">

Cybernews screenshot

The image below shows successful privilege escalation.

<img src="WannaCry Case Study Folder Pics/WCS 7.png">

Cybernews screenshot

### The Lateral Movement Phase

With a growing foothold within the organization's network, the attacker starts to escalate privileges and move laterally, traversing from one compromised system to another. They may use techniques like Pass-the-Hash or Pass-the-Ticket to escalate privileges and impersonate legitimate users, enabling them to access more sensitive resources and expand their control over the network.

During this lateral movement, the attacker may deploy various tools and malware to further their objectives. For example, they might use keyloggers or credential-stealing malware to harvest login credentials of high-privileged users, allowing them to gain even greater control over critical systems and sensitive data.

In this instance, the attacker will deploy ransomware across the network like WannaCry.

Throughout this entire process, the attacker may operate stealthily, attempting to evade detection by leveraging anti-forensic techniques and obfuscating their activities. They might use encryption and tunneling techniques to hide their network traffic and maintain persistence within the compromised systems to ensure long-term access.

# 4. Mitigation Plan:

### **Step 1: User Training and Awareness**

- **Importance of Software Updates**: Users should be educated about the importance of keeping their operating systems and software up to date with the latest security patches. Regular updates can help protect against known vulnerabilities that attackers might exploit.

- **Educate on Ransomware**: Users should be aware of what ransomware is, how it works, and the potential consequences of an infection. This awareness can help users remain vigilant and take appropriate actions to prevent ransomware attacks.

### **Step 2: Access Control and Authentication**

- **Implement Least Privilege**: Users and systems should only have access to the resources and privileges necessary for their roles. This limits the potential damage that can be caused by compromised accounts or systems.
- **Network Segmentation**: Segmenting networks can help contain the spread of malware in the event of a breach. By restricting communication between different parts of the network, organizations can limit the impact of ransomware attacks like WannaCry, which spread laterally across networks.

### **Step 3: Network Security**

- **Network Access Control (NAC)**: Implement NAC solutions to enforce security policies and control access to the network based on the identity and security posture of devices and users. NAC can help prevent unauthorized devices from connecting to the network and limit the spread of malware.

### **Step 4: Endpoint Protection**

- **Endpoint Security Solutions**: Deploy comprehensive endpoint security solutions, such as antivirus software, anti-malware, and host-based intrusion prevention systems (HIPS), to detect and prevent malicious activity on individual devices. These solutions should be regularly updated with the latest threat intelligence and signatures to effectively combat evolving threats like ransomware.

### **Step 5: Security Monitoring, Incident Response, Business Continuity Plan and Disaster Recovery Plan**

- **Continuous Monitoring**: Implement robust security monitoring mechanisms to detect suspicious activity and potential indicators of compromise across the network and endpoints. Continuous monitoring enables early detection of ransomware infections and facilitates rapid response.
- **Incident Response Plan (IRP)**: Develop and regularly update an incident response plan that outlines procedures for responding to ransomware attacks and other security incidents. The plan should include roles and responsibilities, communication protocols, containment strategies, and steps for recovery and mitigation.

- **Business Continuity Plan (BCP)**: Develop a business continuity plan that outlines procedures for maintaining essential business functions and services during and after a ransomware attack. Identify critical systems, processes, and resources, and establish recovery time objectives (RTOs) and recovery point objectives (RPOs) to guide recovery efforts.

- **Backup and Disaster Recovery**: Implement regular backup procedures to ensure the availability and integrity of critical data and systems. Backups should be stored securely and tested regularly to verify their effectiveness in restoring operations in the event of a ransomware attack or data loss incident.

### **Step 6: Compliance and Documentation**

- **Regulatory Compliance**: Organizations should ensure that their cybersecurity practices align with relevant regulatory requirements and industry standards, such as GDPR (General Data Protection Regulation), HIPAA (Health Insurance Portability and Accountability Act), PCI DSS (Payment Card Industry Data Security Standard), and others. Compliance with these regulations often requires documentation of security policies, procedures, and controls related to ransomware prevention and response.

- **Documentation Retention**: Establish procedures for the retention and storage of cybersecurity-related documentation in accordance with regulatory requirements and organizational policies. Maintain documentation in a secure and accessible manner to facilitate audits, investigations, and regulatory inquiries.

### **Step 7: Accurate Inventory, Vulnerability Assessment, and System Hardening**

**Accurate Inventory Management**:

- Maintain an up-to-date inventory of all hardware and software assets within the organization's IT infrastructure. This includes servers, endpoints, network devices, and software applications.
- Document asset details such as device types, configurations, operating systems, installed software, and associated dependencies.
- Regularly reconcile the inventory against the actual state of the infrastructure to identify discrepancies and ensure comprehensive coverage.
- Accurate inventory management facilitates effective vulnerability management and ensures that all systems are properly assessed and protected against ransomware and other security threats.

**Vulnerability Assessment**:

- Conduct regular vulnerability assessments to identify weaknesses and security flaws within the IT infrastructure. Use automated scanning tools and manual techniques to identify vulnerabilities in operating systems, software applications, and network devices.
- Prioritize vulnerabilities based on severity, exploitability, and potential impact on the organization's security posture.
- Document vulnerability assessment findings, including identified vulnerabilities, risk ratings, and recommended remediation actions.
- Integrate vulnerability assessment into the organization's risk management processes to prioritize remediation efforts and allocate resources effectively.

**System Hardening**:

- Implement system hardening measures to reduce the attack surface and strengthen the security posture of IT systems. This involves configuring systems and software according to security best practices and industry standards.
- Document system hardening guidelines and procedures for various types of systems, including servers, endpoints, and network devices.
- Harden operating systems by disabling unnecessary services, removing unnecessary software components, applying security patches, and configuring security settings to minimize exposure to potential vulnerabilities.
- Utilize security configuration baselines and hardening standards provided by reputable sources such as CIS (Center for Internet Security) or NIST (National Institute of Standards and Technology) to guide system hardening efforts.
- Regularly review and update system hardening configurations to address new vulnerabilities, emerging threats, and changes in security requirements.

### **Step 8: Patch Management**

- **Patch Compliance Monitoring**: Monitor patch compliance to ensure that all systems are up to date with the latest security patches. Implement monitoring mechanisms to track patch status, identify missing patches, and remediate non-compliant systems promptly.

### **Step 9: Continuous Improvement**

- **Post-Incident Analysis**: Conduct a thorough post-incident analysis to understand the root causes, impact, and effectiveness of the response to the WannaCry attack. Identify gaps, weaknesses, and areas for improvement in security controls, incident response procedures, and business continuity measures.

- **Lessons Learned**: Extract valuable lessons learned from the WannaCry incident and use them to inform future cybersecurity initiatives. Document insights, observations, and best practices derived from the incident response efforts to guide continuous improvement efforts.

### Step 10: Disable SMBv1

- Since EternalBlue targets the SMBv1 protocol, disable or block SMBv1 across your network, especially if it is not required. SMBv2 or SMBv3 should be used as more secure alternatives.

# 5. MITRE ATT&CKs:

1. **[Active Scanning (T1595)](https://attack.mitre.org/techniques/T1595/)**: WannaCry would actively scan the Local Area Network (LAN) and the internet to identify and infect computers vulnerable to the EternalBlue exploit.

1. **[Malware Development (T1587.001)](https://attack.mitre.org/techniques/T1587/001/)**: An earlier version of WannaCry was circulating in the wild, but its capability to self-propagate via the EternalBlue exploit significantly increased the threat posed by WannaCry.

1. **[Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)**: WannaCry exploited vulnerable SMB network protocols, which are typically intended for internal network use only. By exploiting these, WannaCry could access the targeted device.

More MITRE ATT&CKs related to WannaCry - [WannaCry, Software S0366 | MITRE ATT&CK®](https://attack.mitre.org/software/S0366/)

# 6. CVEs:

[**CVE-2017-0144**](https://nvd.nist.gov/vuln/detail/CVE-2017-0144): Also known as 'SMB Ghost,' is a remote code execution vulnerability in the Microsoft Server Message Block 1.0 (SMBv1) server that can be exploited by sending specially crafted packets to a targeted SMBv1 server, potentially allowing an attacker to execute code on the target server.

[**Microsoft Security Bulletin MS17-010**](https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010): Released in March 2017, patches were released (including a patch for CVE-2017-0144) to address WannaCry, affecting both supported and out-of-support Windows operating system versions.

# 7. Additional Facts:

### **The fully supported Windows 7 was hit the most:**

Roughly 98 percent of the computers affected by the ransomware were running Windows 7, with less than one in a thousand running Windows XP. Even though Windows 7 was fully supported during the attack at the time, people still neglected any updates for it.

### **Who caused the WannaCry Attack:**

In late 2017, the US and UK claimed that the North Korean government was responsible for WannaCry. However, some security researchers challenged this attribution. They argued that the Lazarus Group, based in North Korea, may have created WannaCry, but not necessarily under direct government orders. Others proposed that the evidence within the malware pointing to North Korea could have been intentionally placed to mislead, suggesting that WannaCry could originate from an entirely different region.

### **Who are the Shadow Brokers:**

The Shadow Brokers is a group of hackers that started leaking malware tools and zero-day exploits to the public in 2016. They are suspected of acquiring several exploits developed by the NSA, potentially from an insider attack at the agency.

### **What happened to Marcus Hutchins:**

In his early years Marcus Hutchins who was born in Bracknell, England spent years frequenting malware forums on the dark web, building and selling his own malware. A few months after the WannaCry incident, the FBI arrested Hutchins in Las Vegas, Nevada, for authoring Kronos, a stain of banking malware. Hutchins pleaded guilty on two of the ten charges and at the end of the court case of July 26, 2019, and was sentence to time served and one year of supervised release. 

Today, Hutchins is a cybersecurity specialist, and speaker. He has his own website that showcases him being featured in a Wired magazine, his own cybersecurity blog, booking for his public speaking, his previous work and highlights, and his own YouTube channel and other socials.

You can also find more about him in his Wikipedia biography.

His Website - [Marcus Hutchins](https://marcushutchins.com/)

Wikipedia Biography - [Marcus Hutchins - Wikipedia](https://en.wikipedia.org/wiki/Marcus_Hutchins)

# 8. Sources:

1. Symantec Security Response. “WannaCry ransomware outbreak - what you need to know” *slideshare,* July 26, 2017. [https://www.slideshare.net/ThreatIntel/wannacry-ransomware-outbreak-what-you-need-to-know](https://www.slideshare.net/ThreatIntel/wannacry-ransomware-outbreak-what-you-need-to-know)

1. SentinelOne. “EternalBlue Exploit: What It Is And How It Works” *SentielOne,* May 27, 2019. [https://www.sentinelone.com/blog/eternalblue-nsa-developed-exploit-just-wont-die/#What Is Eternalblue](https://www.sentinelone.com/blog/eternalblue-nsa-developed-exploit-just-wont-die/#What%20Is%20Eternalblue)?

1. Fruhlinger, Josh. “WannaCry explained: A perfect ransomware storm | CSO Online.” *CSO Online,* Aug 24, 2022. [https://www.csoonline.com/article/563017/wannacry-explained-a-perfect-ransomware-storm.html](https://www.csoonline.com/article/563017/wannacry-explained-a-perfect-ransomware-storm.html)

1. Burdova, Carly. “What Is EternalBlue and Why Is the MS17-010 Exploit Still Relevant?” *Avast,* June 18, 2022. [https://www.avast.com/c-eternalblue?utm_medium=affiliate&utm_source=commissionjunction&utm_campaign=100357191&utm_content=15490250&couponfield=yes&cjevent=73f7fcd30529bc3df254ae74890a68f5f7ecd1ecdd256d24e&trafficSource=affiliate&partnerid=100357191&programtype=CJ&clickID=4aafdb86e51911ee835dda6f0a82b832&cjid=100357191](https://www.avast.com/c-eternalblue?utm_medium=affiliate&utm_source=commissionjunction&utm_campaign=100357191&utm_content=15490250&couponfield=yes&cjevent=73f7fcd30529bc3df254ae74890a68f5f7ecd1ecdd256d24e&trafficSource=affiliate&partnerid=100357191&programtype=CJ&clickID=4aafdb86e51911ee835dda6f0a82b832&cjid=100357191)

1. Cybernews Team. “Unraveling EternalBlue: inside the WannaCry’s enabler” *cybernews,* Nov 15, 2023. [https://cybernews.com/security/eternalblue-vulnerability-exploit-explained/](https://cybernews.com/security/eternalblue-vulnerability-exploit-explained/)

1. Cloudflare. “What was the WannaCry ransomware attack?” *Cloudflare.* [https://www.cloudflare.com/learning/security/ransomware/wannacry-ransomware/](https://www.cloudflare.com/learning/security/ransomware/wannacry-ransomware/)

1. Liptak, Andrew. “WannaCry Ransomware: all the updates on the cyberattack” *The Verge,* Dec 18, 2017. [https://www.theverge.com/2017/5/14/15638026/wannacry-ransomware-updates-cyberattack-cybersecurity](https://www.theverge.com/2017/5/14/15638026/wannacry-ransomware-updates-cyberattack-cybersecurity)

1. Redmiles, Elissa & The Conversation US. “Why Installing Software Updates Makes Us WannaCry” *Scientific American,* May 16, 2017. [https://www.scientificamerican.com/article/why-installing-software-updates-makes-us-wannacry/](https://www.scientificamerican.com/article/why-installing-software-updates-makes-us-wannacry/)

1. Automox Team, “6 Reasons Why Companies Don't Patch” *Automox,* Aug 10, 2017. [https://www.automox.com/blog/6-reasons-companies-dont-patch](https://www.automox.com/blog/6-reasons-companies-dont-patch)
