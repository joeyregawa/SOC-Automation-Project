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

TheHive Installation Workflow:
-Create Wazuh Droplet
-Update and Upgrade the System
-Install Wazuh

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
- Using your own machine terminal (simply type `ssh root@<your server IP address>`) and you need to run as the administrator (if you are using windows power shell) or your super user if you are using ubuntu terminal.

### **2.2.2 Update and Upgrade the System, Install and Acess Wazuh:**

`sudo apt-get update && sudo apt-get upgrade`

`curl -sO https://packages.wazuh.com/4.10/wazuh-install.sh && sudo bash ./wazuh-install.sh -a`

Take note of the generated password for the "admin" user from Wazuh 

Access the Wazuh Web Interface: Login to Wazuh using the user and password provide by Wazuh and enter the Wazuh server’s public IP address with `HTTPS://<your wazuh server ip address>`:

![alt text](../images/Wazuh.png)

![alt text](<../images/Wazuh main page.png>)

# **3. Install TheHive**

TheHive Installation Workflow:
-Create TheHive Droplet
-Update and Upgrade the System
-Install Dependencies
-Install Java
-Install Cassandra (Cassandra is database that used by TheHive for storing data.)
-Install Elasticsearch ( Elasticsearch is used by TheHive for indexing and searching data.)
-Install TheHive

## **3.1. Create a Droplet on DigitalOcean and Choose the Operating System:**

*note: for TheHive server droplet setup at DigitalOcean is the same as setup Wazuh server droplet*

![alt text](<../images/TheHive Droplet 1.png>)

## **3.2. Update and Upgrade the System:**

        sudo apt-get update && sudo apt-get upgrade

## ** 3.3. Install Dependencies**

        apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release`

## ** 3.4. Install Java**

        wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
        echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
        sudo apt update
        sudo apt install java-common java-11-amazon-corretto-jdk
        echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
        export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"

## ** 3.5. Install Cassandra**

        wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
        echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
        sudo apt update
        sudo apt install cassandra

## ** 3.6. Install Elasticsearch**

`wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg`
`sudo apt-get install apt-transport-https`
`echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list`
`sudo apt update`
`sudo apt install elasticsearch`

### ** 3.6.1. Elasticsearch Configuration**

Create a jvm.options file in the /etc/elasticsearch/jvm.options.d directory and include the following settings to enhance Elasticsearch performance:

`-Dlog4j2.formatMsgNoLookups=true`
`-Xms2g`
`-Xmx2g`

## ** 3.6. Install TheHive**

`wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg`
`echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list`
`sudo apt-get update`
`sudo apt-get install -y thehive`

By default TheHive will generate Username and Password, and we need to take a note of the username and password

`Username: admin@thehive.local`
`Password: secret`

# **4. Configure Wazuh and TheHive**