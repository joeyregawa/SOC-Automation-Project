# **SOC Automation Project Setup**

# **1. Install and Configure WIndows 10 Machine with Sysmon**
## **1.1. WIndows 10 Machine Installation**

In this project we will install Windows 10 Machine on VirtualBox

![alt text](<../images/Windows 10 Machine.png>)

## **1.2. Install and Configure Sysmon on Windows 10 Machine**

### **1.2.1. Download and Install** 
[SYSMON](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### **1.2.2. Download Sysmon Configuration Files** 
[Sysmon Modular Config](https://github.com/olafhartong/sysmon-modular)

![alt text](<../images/Sysmon Modular Config 1.png>)

![alt text](<../images/Sysmon Modular Config 2.png>)

### **1.2.3. Extract the Sysmon zip file and move the Sysmon config file to the extracted Sysmon zip folder** 

![alt text](<../images/Extract Sysmon.png>)

### **1.2.4. Install and Check Service, Event Viewer to Ensure Sysmon Was Installed Correctly** 

![alt text](<../images/Event Viewer.png>)

![alt text](../images/Services.png)

# **2. Setup Wazuh Server**

In this project we will depoy Wazuh server on Cloud Services (DigitalOcean)

## **2.1. Create a Droplet on DigitalOcean and Choose the Operating System:**

![alt text](<../images/Wazuh Droplet 1.png>)

In this project we will choose Ubuntu Machine

![alt text](<../images/Wazuh Droplet 2.png>)

![alt text](<../images/Wazuh Droplet 3.png>)

### **2.1.1 Set Up Firewall:**
we need a firewall to prevent unauthorized access and external scan spams by modifying the inbound rules to allow access only from our own IP address (can be check with whatismyipaddress website)

![alt text](<../images/DigitalOcean Firewall 1.png>)

### **2.1.2 After setting up the firewall rules, we apply the firewall to our Wazuh Droplet:**

![alt text](<../images/DigitalOcean Firewall 2.png>)

## **2.2. Wazuh Server Access and Wazuh-Manager Installation:**

### **2.2.1 Access the Wazuh Server:**
There are 2 ways to access the Wazuh server:
- Using DigitalOcean Console
- Using your own machine terminal (simply type `ssh root@<your server IP address>`)

