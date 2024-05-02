# THM: Warzone 1

In this short CTF we have received alert during our SOC shift with signatures such **Potentially Bad Traffic** and **Malware Command and Control Activity detected**. Our race against the clock starts.

Navigate to the room [here](https://tryhackme.com/r/room/warzoneone) to start our investigation.

### What was the alert signature for **Malware Command and Control Activity Detected**?

Alert signature feature is built in **Brim**, so fire it up, upload the .pcap file from **Desktop** and use following query to search for alerts and filter only alert signatures **`event_type=”alert” | count () by alert.signature`** All we need to do now is to pick the right one:

![Untitled](THM%20Warzone%201%20f9e5dc4c944d4e89b1fcb3a4ca891b43/Untitled.png)

**Answer:** ET MALWARE MirrorBlast CnC Activity M2

### What is the source IP address? Enter your answer in a **defanged** format.

Since we have only single alert, answer is pretty straight forward. For correct answer use [CyberChef](https://cyberchef.org/) defang IP address.

**Answer:** 172[.]16[.]1[.]102

### What IP address was the destination IP in the alert? Enter your answer in a **defanged** format.

Since we have only single alert, answer is pretty straight forward. For correct answer use [CyberChef](https://cyberchef.org/) defang IP address.

**Answer:** 169[.]239[.]128[.]11

### Inspect the IP address in VirsusTotal. Under **Relations > Passive DNS Replication**, which domain has the most detections? Enter your answer in a **defanged** format.

Use destination IP address for VirusTotal check. For correct answer use [CyberChef](https://cyberchef.org/) defang URL.

**Answer:** fidufagios[.]com

### Still in VirusTotal, under Community, what threat group is attributed to this IP address?

Navigate to > **Community** for answer

**Answer:** TA505

### What is the malware family?

Navigate to > **Community** for answer

**Answer:** mirrorblast

### Do a search in VirusTotal for the domain from question 4. What was the majority file type listed under Communicating Files?

Navigate to > **Relations** for answer.

**Answer:** Windows Installer

### Inspect the web traffic for the flagged IP address; what is the user-agent in the traffic?

Lets filter for HTTP traffic and narrow down the destination traffic based on malicious IP - use this query `path=”http” | id.resp_h=169.239.128.11`

Pick one of the http packets → right click and pick **Open details**

![Untitled](THM%20Warzone%201%20f9e5dc4c944d4e89b1fcb3a4ca891b43/Untitled%201.png)

On right side pane with HTTP fields will appear - search for **user_agent**

**Answer:** REBOL View 2.7.8.3.1

### Retrace the attack; there were multiple IP addresses associated with this attack. What were two other IP addresses? Enter the IP addressed defanged and in numerical order. (format: IPADDR,IPADDR)

Lets filter for HTTP traffic, exclude the first detected address and sort by timestamp using query `path=”http” **| id.resp_h!=169.239.128.11 | sort ts`  

![Untitled](THM%20Warzone%201%20f9e5dc4c944d4e89b1fcb3a4ca891b43/Untitled%202.png)

So we have some options to check via **VirusTotal**. For correct answer use [CyberChef](https://cyberchef.org/) defang IP address.

**Answer:** 185[.]10[.]68[.]235,192[.]36[.]27[.]92

### What were the file names of the downloaded files? Enter the answer in the order to the IP addresses from the previous question. (format: file.xyz,file.xyz)

Lets user query `filename id.resp_h!=169.239.128.11` which will filter for downloaded files and will exclude the first detected address, this will narrow the search for few files which we will observe during inspection of fields.

**Answer:** filter.msi,/10opd3r_load.msi

### Inspect the traffic for the first downloaded file from the previous question. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files?

Lets re-check from which source address the files came from - is very easy. In Brim navigate to **File Activity** and check the address. 

![Untitled](THM%20Warzone%201%20f9e5dc4c944d4e89b1fcb3a4ca891b43/Untitled%203.png)

Now use this address as source IP in Wireshark to filter for HTTP traffic coming from this host. Since HTTP is un-encrypted we can use **follow TCP stream** to inspect the whole conversation.

![Untitled](THM%20Warzone%201%20f9e5dc4c944d4e89b1fcb3a4ca891b43/Untitled%204.png)

Scroll to very bottom of the page to find the answers.

**Answer:** C:\ProgramData\001\arab.exe,C:\ProgramData\001\arab.bin

### Now do the same and inspect the traffic from the second downloaded file. Two files will be saved to the same directory. What is the full file path of the directory and the name of the two files?

Pretty much same approach, good luck.

**Answer:** C:\ProgramData\Local\Google\rebol-view-278-3-1.exe

Thanks for tuning in