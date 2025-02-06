# **SOC Automation Project**

Welcome to the SOC (Security Operations Center) Automation project repository! This project is designed to improve security operations by automating routine tasks, coordinating responses to security incidents, and boosting overall effectiveness in detecting and addressing threats. 

This project was greatly enhanced by the insights and tutorials from the [MyDFIR](https://www.youtube.com/playlist?list=PLEd_qaF8wpnXgdngqfsQtYYGM-IdtuxmC) YouTube channel. Their detailed videos played a crucial role in understanding and executing the different elements of the SOC Automation Project.

## **[Click here to visit SOC Automation Project Setup!](./SOC%20Automation%20Setup/Setup.md)**

# **1. Introduction**
## **1.1. Overview**
The SOC Automation Project is focused on developing an automated Security Operations Center (SOC) workflow to optimize event monitoring, alerting, and incident response. Utilizing robust open-source tools like Wazuh, Shuffle, and TheHive, the project aims to improve the efficiency and performance of SOC operations. It includes configuring a Windows 10 client with Sysmon for detailed event logging, Wazuh for event management and alerting, Shuffle for automating workflows, and TheHive for case management and coordinated response actions.

### SOC Automation Project Diagram: ###

![alt text](<images/SOC automation Diagram.jpg>)

## **1.2. Project Objectives:**
- **Automate Event Collection and Analysis:** Ensure security events are collected and analyzed in real-time with minimal manual intervention, enabling proactive threat detection and swift responses.
- **Optimize Alerting Process:** Automate the creation and distribution of alerts to relevant systems and personnel, reducing response time and preventing critical incidents from being overlooked.
- **Enhance Incident Response:** Automate response actions to security incidents, improving speed, consistency, and effectiveness in mitigating threats.
- **Boost SOC Productivity:** Reduce the workload of SOC analysts by automating repetitive tasks, allowing them to focus on more critical issues and strategic objectives.

# **2. Requirement and Tools**
## **2.1. Hardware Requirement**
  - A host that can run multiple VM
  - Sufficient of RAM, CPU and disk storage to contain the VMs
## **2.2. Software Requirement**
  - VMware      : is used for managing the virutal machines.
  - Ubuntu 24.04: is used for deploying Wazuh-manager and theHive
  - Sysmon      : is used to monitor event logging and telemetry.
  - Windows 10  : windows 10 will act as Wazuh agent client machine for generating realistic security and testing the SOC automation workflow
## **2.3. Tools and Platform**
  - Wazuh      : open-source security platform that helps users detect, respond to, and prevent threats
  - Shuffle    : an open-source SOAR platform that allows you to create workflows to automate various tasks within your SEIM stack or other environments.
  - theHive    : a scalable, open-source Security Incident Response Platform designed for SOCs to efficiently manage and resolve incidents.
  - VirusTotal : online service used to analyze suspicious files and URLs to detect malware and malicious content by scanning them against a large collection of antivirus engines and website scanners.
  - VirtualBox or Cloud Services: in this project DigitalOcean is used to deploy Wazuh and theHive, and VirtualBox is used for running the Windows 10 machine.

# **3. Study Case**
This project will showcase SOC Automation, which is designed to improve security operations by automating routine tasks, coordinating responses to security incidents, and boosting overall effectiveness in detecting and addressing threats.

To demonstrate how this SOC automation works, Mimikatz will be used as a simulated attack. Mimikatz is an application used by red teams or attackers to collect, gather, or extract credentials from a target machine, Custom rules at Wazuh is used to detect the Original File Name. The Original File Name custome rule is used because whenever the attackers rename it, it will trigger the alert since it is tracking the Original File Name.

## **3.1. Visual Representation**
### **3.1.1. WIndows 10 Machine (Wazuh-agent) execute Mimikatz and send event to Wazuh-Manager** 

![alt text](<images/Mimikatz rename execute.png>)

Ref 1: Mimikatz file name has been rename and Windows Machine execute the Mimikatz rename file.

### **3.1.2. Wazuh-Manager Trigger Alerts & Perform Responsive Action** 

![alt text](<images/Wazuh_manager MITRE-ATT&CK event .png>)

![alt text](<images/Wazuh_manager Threat Hunting event .png.png>)

Ref 2: Wazuh-Manager trigger alerts.

### **3.1.3. Shuffle Recieve and Demonstrating the Automated Process of Alerting and Incident Response.** 

![alt text](<images/Shuffle Workflow.png>)

Ref 3: Shuffle recieve alerts and perform automated process of alerting and incident response.

### **3.1.4. Shuffle Recieve Back the Data From VirusTotal and Send It to TheHiveto Create Alert.** 

![alt text](<images/Virus Total Recieve the data.png>)

Ref 4: Virus Total Recieve the data.

### **3.1.5. Shuffle send SHA256 Data to VirusTotal to Check Reputation Score.** 

    {
	"_id":"~8134832"
	"_type":"Alert"
	"_createdBy":"shuffle@test.com"
	"_createdAt":1738756289644
	"type":"Internal"
	"source":"Wazuh"
	"sourceRef":"Rule:100002"
	"title":"Mimikatz Ussage Detected"
	"description":"Mimikatz Detected on host: DESKTOP-4VDO2G0"
	"severity":2
	"severityLabel":"MEDIUM"
	"date":1738756289525
	"tags":[...]1 item
	"tlp":2
	"tlpLabel":"AMBER"
	"pap":2
	"papLabel":"AMBER"
	"follow":true
	"customFields":[]0 items
	"observableCount":0
	"status":"New"
	"stage":"New"
	"summary":"Details about the Mimikatz detection"
	"extraData":{}0 items
	"newDate":1738756289548
	"timeToDetect":0
     }
Ref 5.1 : Shuffle send data to TheHive to generate alert.

![alt text](<images/Shuffle generate alert 1.png>)

![alt text](<images/Shuffle generate alert 2.png>)

*note:Refer to the body part of TheHive in Shuffle to determine what to include in these fields. Save and Run again the workflow to see the alert update.*

![alt text](<images/Enhanced Shuffle Alert.png>)

Ref 5.2 : TheHive recieve data and generate alert.

### **3.1.5. Send an email to the SOC analyst to begin the investigation.** 

![alt text](<images/Shuffle Send Email to SOC analyst.png>)

Ref 6 :  Send an email to the SOC analyst to begin the investigation.

# **4. Conclusion**

We have successfully set up and configured the SOC Automation Lab, incorporating Wazuh, TheHive, and Shuffle to automate event monitoring, alerting, and incident response. This foundation lays the groundwork for future customization and growth of automation workflows to meet our specific SOC requirements. Key steps and achievements of this lab include:

- Configuring and setting up a Windows 10 client with Sysmon to generate comprehensive event data.
- Deploying Wazuh as the core platform for event management and alert notifications.
- Installing and configuring TheHive for case management and orchestrated responses.
- Generating telemetry from Mimikatz and setting up custom alerts in Wazuh.
- Integrating Shuffle as the SOAR platform for automating workflows.
- Developing an automated workflow to extract file hashes, verify reputation scores via VirusTotal, generate alerts in TheHive, and notify SOC analysts through email.

This project has provided valuable hands-on experience in implementing an automated SOC workflow using powerful open-source tools. We can now apply this knowledge to enhance the organization's security operations, improve incident response times, and optimize SOC processes.

It is important to continually refine and adapt automation workflows in response to evolving threats, new tools, and changing business needs. Regularly review and update SOC playbooks, integrate additional threat intelligence sources, and explore advanced features of the tools utilized in this lab.

By adopting automation and harnessing the capabilities of Wazuh, TheHive, and Shuffle, you can create a more efficient, effective, and resilient SOC that proactively detects and responds to security incidents.

# **5. Refferences**
https://www.youtube.com/playlist?list=PLEd_qaF8wpnXgdngqfsQtYYGM-IdtuxmC
