# Elevate Labs Cybersecurity Internship - Task 1

## Local Network Port Scanning and Analysis

### Objective

The objective of this task was to perform network reconnaissance on a local network to discover active hosts and identify open ports. This process helps in understanding the network's exposure and identifying potential security vulnerabilities associated with running services.

---

### Methodology

1.  **Tool Selection:** The primary tool used for this task was **Nmap (Network Mapper)**, a powerful open-source tool for network discovery and security auditing.

2.  **Network Discovery:** The local network range was identified by inspecting the host machine's network configuration. The host's IP address was `192.168.238.222` with a subnet mask of `255.255.255.0`, which corresponds to a network range of `192.168.238.0/24`.

3.  **Scanning Technique:** A **TCP SYN Scan (`-sS`)** was performed. This "half-open" scanning technique is fast and relatively stealthy, as it does not complete a full TCP connection, making it less likely to be logged by target systems.

4.  **Command Execution:** The scan was executed from a Windows command prompt with administrator privileges using the following command:
    ```
    nmap -sS -oN scan_results.txt 192.168.238.0/24
    ```
    The results were saved to the `scan_results.txt` file for analysis.

---

### Analysis of Scan Results

The Nmap scan identified three active hosts on the `192.168.238.0/24` network. Below is a detailed analysis of each host.

#### Host 1: `192.168.238.41`

* **Open Ports:**
    * `53/tcp`: `domain` - Domain Name System (DNS)
* **Analysis:** This host is likely the network's primary DNS resolver, which is a fundamental network service. In most home networks, this role is fulfilled by the router.
* **Security Risk:** **Low.** A DNS server is essential for network functionality. While it can be a target for specific attacks (like DNS spoofing), its presence on a local network is normal and expected.

#### Host 2: `192.168.238.138`

* **Open Ports:**
    * `8008/tcp`: `http` - Alternative HTTP Port
    * `8009/tcp`: `ajp13` - Apache JServ Protocol
    * `8443/tcp`: `https-alt` - Alternative HTTPS Port
    * `9000/tcp`: `cslistener` - Various possible services
* **Analysis:** The presence of HTTP, HTTPS, and AJP ports strongly suggests this device is running a web server, likely Apache Tomcat. Port 9000 is used by various applications, sometimes for development servers or management consoles.
* **Security Risk:** **Medium.** Web servers are common attack vectors. The risk depends on the software version, its configuration, and whether it is patched against known vulnerabilities (e.g., the "Ghostcat" vulnerability associated with AJP). Unsecured web applications running on these ports could expose the device and network to significant risk.

#### Host 3: `192.168.238.222` (This Host)

* **Open Ports:**
    * `135/tcp`: `msrpc` - Microsoft RPC
    * `139/tcp`: `netbios-ssn` - NetBIOS Session Service
    * `445/tcp`: `microsoft-ds` - Server Message Block (SMB) over TCP
* **Analysis:** These ports are standard for Windows networking, enabling file sharing, printer sharing, and other remote administration functions. This host is the machine the scan was run from.
* **Security Risk:** **Medium to High.** While necessary for many Windows functions, these ports are historically high-value targets for attackers. The SMB protocol, in particular, has been exploited by famous malware like WannaCry and NotPetya. The risk is significantly mitigated if the operating system is fully patched and strong passwords are in use.

---

### Interview Questions & Answers

**1. What is an open port?**
An open port is a network port on a computer that is configured to accept incoming packets from the network. It indicates that a specific service or application is actively listening for connections on that port number.

**2. How does Nmap perform a TCP SYN scan?**
A TCP SYN scan is a "half-open" scan. Nmap sends a TCP packet with the SYN (synchronize) flag set to a target port. If the port is open, the target responds with a SYN/ACK (synchronize/acknowledge) packet. Nmap receives this response, marks the port as open, and immediately sends a RST (reset) packet to tear down the connection before it is fully established, making the scan fast and stealthy.

**3. What risks are associated with open ports?**
Open ports themselves are not risks, but the services running on them can be. The risks include:
* **Vulnerable Software:** The service may have known vulnerabilities that an attacker can exploit to gain unauthorized access.
* **Misconfiguration:** The service might be poorly configured (e.g., using default passwords), making it easy to compromise.
* **Information Leakage:** Services can leak information about the system, such as software versions, which helps an attacker plan an attack.
* **Denial of Service (DoS):** Open services can be targeted by DoS attacks, overwhelming them with traffic and making them unavailable.

**4. Explain the difference between TCP and UDP scanning.**
* **TCP Scanning:** TCP is a connection-oriented protocol. Scanning involves a "three-way handshake" (or a part of it, like in a SYN scan). It is reliable because the scanner gets a definitive response if a port is open.
* **UDP Scanning:** UDP is a connectionless protocol. When a scanner sends a UDP packet to a port, there is no guaranteed response. If the port is closed, the system usually sends back an "ICMP Port Unreachable" message. If the port is open, it might not respond at all. This makes UDP scanning slower and less reliable than TCP scanning.

**5. How can open ports be secured?**
* **Principle of Least Privilege:** Close any ports that are not absolutely necessary.
* **Firewalls:** Use a firewall to create rules that restrict access to open ports, allowing only trusted IP addresses or networks to connect.
* **Patch Management:** Keep the software and services running on open ports updated and patched against known vulnerabilities.
* **Strong Configuration:** Change default credentials, disable unnecessary features, and follow security best practices for configuring the service.

**6. What is a firewall's role regarding ports?**
A firewall acts as a gatekeeper for network traffic. Its role regarding ports is to enforce access control rules. It can be configured to:
* **Block ports:** Prevent any traffic from reaching a specific port.
* **Allow ports:** Explicitly permit traffic to a specific port.
* **Filter traffic:** Allow traffic to a port only from specific source IP addresses or based on other criteria, effectively controlling who can communicate with the services running on the machine.

**7. What is a port scan and why do attackers perform it?**
A port scan is the process of systematically probing a server or host for open ports. Attackers perform port scans as a primary step in network reconnaissance. It allows them to:
* Identify which services are running on a target system.
* Determine the operating system and software versions.
* Find potential vulnerabilities in the running services that they can later exploit to gain access.

**8. How does Wireshark complement port scanning?**
Wireshark is a packet analyzer. It complements port scanning by providing a detailed, low-level view of the network traffic generated during the scan. While Nmap tells you *what* ports are open, Wireshark can show you *how* Nmap discovered that information. It can be used to:
* Troubleshoot why a scan might be failing.
* Analyze the exact responses from a target to understand its behavior.
* Detect if a port scan is being performed on your own network by observing the suspicious patterns of traffic.
