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
 - Create Wazuh Droplet
 - Update and Upgrade the System
 - Install Wazuh

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

        sudo apt-get update && sudo apt-get upgrade

        curl -sO https://packages.wazuh.com/4.10/wazuh-install.sh && sudo bash ./wazuh-install.sh -a

Take note of the generated password for the "admin" user from Wazuh 

Access the Wazuh Web Interface: Login to Wazuh using the user and password provide by Wazuh and enter the Wazuh server’s public IP address with `HTTPS://<your wazuh server ip address>`:

![alt text](../images/Wazuh.png)

![alt text](<../images/Wazuh main page.png>)

# **3. Install TheHive**

TheHive Installation Workflow:
 - Create TheHive Droplet
 - Update and Upgrade the System
 - Install Dependencies
 - Install Java
 - Install Cassandra (Cassandra is database that used by TheHive for storing data.)
 - Install Elasti csearch ( Elasticsearch is used by TheHive for indexing and searching data.)
 - Install TheHive

## **3.1. Create a Droplet on DigitalOcean and Choose the Operating System:**

*note: for TheHive server droplet setup at DigitalOcean is the same as setup Wazuh server droplet*

![alt text](<../images/TheHive Droplet 1.png>)

## **3.2. Update and Upgrade the System:**

        sudo apt-get update && sudo apt-get upgrade

## **3.3. Install Dependencies**

        apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release`

## **3.4. Install Java**

        wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
        echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
        sudo apt update
        sudo apt install java-common java-11-amazon-corretto-jdk
        echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
        export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"

## **3.5. Install Cassandra**

        wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
        echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
        sudo apt update
        sudo apt install cassandra

## **3.6. Install Elasticsearch**

        wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
        sudo apt-get install apt-transport-https
        echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
        sudo apt update
        sudo apt install elasticsearch

### **3.6.1. Elasticsearch Configuration**

Create a jvm.options file in the /etc/elasticsearch/jvm.options.d directory and include the following settings to enhance Elasticsearch performance:

        -Dlog4j2.formatMsgNoLookups=true
        -Xms2g
        -Xmx2g

## **3.6. Install TheHive**

        wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
        echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
        sudo apt-get update
        sudo apt-get install -y thehive

By default TheHive will generate Username and Password, and we need to take a note of the username and password

        Username: admin@thehive.local
        Password: secret

# **4. Configure Wazuh-Agent and TheHive**

## **4.1. TheHive Configuration**
### **4.1.1. Configure Cassandra: Cassandra will ack as thehive database. To modify the `cassandra.yaml` file:**

        nano /etc/cassandra/cassandra.yaml

 - set search for `listen_address` and change it to thehive public IP address:

![alt text](<../images/Cassandra Config 1.png>)

 - set search for `rpc_address` and change it to thehive public IP address:

![alt text](<../images/Cassandra Config 2.png>)

 - Change the seed address under the `seed_provider` section. Enter TheHive's public IP in the `seeds` field:

![alt text](<../images/Cassandra Config 3.png>)

 - Stop the Cassandra service:

        systemctl stop cassandra.service

 - Remove the old Cassandra data files since we installed TheHive using the package:

        rm -rf /var/lib/cassandra/*

 - Start the Cassandra service again:

        systemctl start cassandra.service

 - To ensure Cassandra service is running: 

        systemctl status cassandra.service

![alt text](<../images/Cassandra Config 4.png>)

### **4.1.2.  Configure Elasticsearch: Elasticsearch is used to manage data indices or querying data in thehive. to configure it by modifying the `elasticsearch.yml` file:**

        nano /etc/elasticsearch/elasticsearch.yml

 - We can change the cluster name. Uncomment the `node.name` field. Uncomment the `network.host` field and set the IP to TheHive's public IP.

![alt text](<../images/Elasticsearch Config 1.png>)

You can choose to uncomment the `http.port` field (the default port is 9200). Additionally, you may uncomment the `cluster.initial_master_nodes` field and remove `node-2` if it's not needed.

 - Start and enable the Elasticsearch service:

        systemctl start elasticsearch
        systemctl enable elasticsearch

To ensure Elasticsearch is running properly:

        systemctl status elasticsearch

![alt text](<../images/Elasticsearch Config 2.png>)

### **4.1.3.  Configure TheHive: Before setting up the TheHive configuration file, we need to ensure that the TheHive user and group have the appropriate access to the required file path:**

        ls -la /opt/thp

![alt text](<../images/TheHive Config 1.png>)

 - This indicate that root has access to thehive user and group for specific directories. we need to change it by using:

        chown -R thehive:thehive /opt/thp

 - This command assigns the ownership of the specified directories to the thehive user and group.

![alt text](<../images/TheHive Config 2.png>)


- Configure TheHive's configuration file:

        nano /etc/thehive/application.conf

![alt text](<../images/TheHive Config 3.png>)

 - Change the s`torage.hostname` to thehive public ip address. Set the `cluster-name` to the same name values as the Cassandra  `cluster-name` . Change the index.search.hostname to  thehive public ip address. At the bottom, change the `application.baseUrl` to thehive public ip address.
 - By default, TheHive has both Cortex (data enrichment and response) and MISP (threat intelligence platform) enabled.

 - Run and check thehive to ensure it is running properly.

        systemctl start thehive
        systemctl enable thehive
        systemctl status thehive

![alt text](<../images/TheHive Config 4.png>)

*Note: if thehive cannot be access or won’t start, there is a propblem that Cassandra, Elasticsearch, or thehive not running properly*

 - If all services are running, access thehive from a web browser using thehive’s public IP and port 9000:

![alt text](<../images/TheHive Config 5.png>)

 - By default thehive provide us with username and password. we will use it to login.    

        Username: admin@thehive.local Password: secret
 
![alt text](<../images/TheHive Config 6.png>)



 - Since we will be using windows machine, add a Windows Wazuh-agent.

![alt text](<../images/Wazuh-Agent Config 1.png>)
![alt text](<../images/Wazuh-Agent Config 2.png>)
![alt text](<../images/Wazuh-Agent Config 3.png>)

# **5. Generate Telemetry and Custom Alerts**

## **5.1. Configure Sysmon Event Forwarding to Wazuh**
Navigate to `C:\Program Files (x86)\ossec-agent` and open the `ossec.conf` file with a text editor (e.g., Notepad). Optional: make a copy of `ossec.conf` for backup

## **5.2. Add Sysmon Event Forwarding into Wazuh ossec config and Save the `ossec.conf`**

![alt text](<../images/Generate Telemetry and Custom Alerts 1.png>)

*Optional: you can keep the Powershell, Application, System and Security logs to forward it to Wazuh. Since we will be focusing in Sysmon even, we will exclude the Powershell, Application, System and Security logs.*

## **5.3. Restart the Wazuh-Agent**

![alt text](<../images/Wazuh-Agent Config 2.png>)

## **5.4. Check the Sysmon Event on Wazuh.**
Click the more button, continue click the threat hunting button. In the threat hunting page, click event button and search for sysmon.

![alt text](<../images/Wazuh-Agent Config 3.png>)

# **6. Download & Generate Mimikatz Telemetry**

*Mimikatz is used by red teams or attackers to collect or gather or extract credentials from target machine.*

## **6.1. Download Mimikatz**

Before dowloading Mimikatz to Windows 10 machine, you may need to temporarily disable Windows Defender or exclude the download directory from scanning. Dowload Mimikatz (https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919)

![alt text](<../images/Mimikatz 1.png>)

## **6.2. Execute Mimikatz**
Use PowerShell, navigate to the directory where Mimikatz is downloaded, and execute it.

![alt text](<../images/Mimikatz 2.png>)

## **6.3. Configure Wazuh to Log All Events**
Open Wazuh-manager terminal. Before modifying the `ossec.conf` file, create a copy for backup `cp /var/ossec/etc/ossec.conf ~/ossec-backup.conf`. Change the <logall> and <loggal_json> to `yes`, continue by resarting the wazuh-manager to run the changes we made.

![alt text](<../images/Configure Wazuh to Log All Events 1.png>)

To apply change we need to restrat the Wazuh-Manager

        systemctl restart wazuh-manager.service

This configuration directs Wazuh to store all logs in the /`var/ossec/logs/archives/ directory`.

## **6.4. Configure Filebeat**
 To enable Wazuh to ingest the archived logs we made earlier, we need to modify the Filebeat configuration 
        
        nano /etc/filebeat/filebeat.yml

under the `filebeat.modules` change the `archives: enabled : true`  , than restart the filebeat (`systemctl restart filebeat`).

![alt text](<../images/Configure Wazuh to Log All Events 2.png>)

## **6.5. Create a New Index in Wazuh**
After Filebeat and ossec.conf have been updated, create New Index by opening the menu, than choose the dashboard management, index patterns, create index pattern. 

Create a new index named `wazuh-archives-*` to cover all archived logs. On the next page, select `"timestamp"` as the time field and create the index.

![alt text](<../images/Configure Wazuh to Log All Events 3.png>)

*Cofigurations is need because only logs or event that trigger by rules will show up*

## **6.6. Troubleshoot Mimikatz Logs**
To check if Mimikatz logs are being archived, use cat and grep commands on the archived logs in the Wazuh manager CLI:

        cat /var/ossec/logs/archives/archives.log | grep -i mimikatz

![alt text](<../images/Configure Wazuh to Log All Events 4.png>)

If no Mimikatz events are present in the archives, it indicates that no Mimikatz event was generated, and you won't find any related events in the Wazuh web interface.

## **6.67 Relaunch Mimikatz**
Relaunch Mimikatzt on the Windows Machines and check the event viewers to ensure that Sysmon is capturing Mimikatz events.

![alt text](<../images/Configure Wazuh to Log All Events 5.png>)

archive file on Wazuh-Manager that capture the Mimikatz logs:

![alt text](<../images/Configure Wazuh to Log All Events 6.png>)
![alt text](<../images/Configure Wazuh to Log All Events 7.png>)
![alt text](<../images/Configure Wazuh to Log All Events 8.png>)






































