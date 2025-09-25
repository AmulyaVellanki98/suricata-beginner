Learning suricata:

<img width="936" height="259" alt="image" src="https://github.com/user-attachments/assets/1609adfc-7a63-4886-8a38-373284ec5c2d" />

This rule consists of three components: an action, a header, and rule options.

# Suricata Rule Actions

In Suricata, the **action** is the first part of a rule (also called a signature). It tells Suricata what to do if the traffic matches the rule conditions. The most common actions are `alert`, `drop`, `pass`, and `reject`.

## Common Actions

### 1. `alert` Action
The `alert` action generates an alert but does not block the traffic. This is typically used when Suricata is running in IDS (Intrusion Detection System) mode.

**Example:**
```
alert tcp any any -> any 80 (msg:"HTTP traffic detected"; sid:1001; rev:1;)
```
This rule will generate an alert if any TCP traffic is going to port 80 (HTTP).

### 2. `drop` Action
The `drop` action generates an alert and blocks/drops the traffic. This is used when Suricata is running in IPS (Intrusion Prevention System) mode.

**Example:**
```
drop tcp any any -> any 23 (msg:"Telnet attempt blocked"; sid:1002; rev:1;)
```
This rule will block and alert on traffic going to port 23 (Telnet).

### 3. `pass` Action
The `pass` action allows traffic to go through even if other rules would block it. This is useful for creating exceptions for trusted traffic.

**Example:**
```
pass tcp 192.168.1.10 any -> any 80 (msg:"Allow web traffic from trusted host"; sid:1003; rev:1;)
```
This rule allows all HTTP traffic from the trusted host 192.168.1.10.

### 4. `reject` Action
The `reject` action blocks the traffic and also sends an error message back to the sender, such as a TCP reset or ICMP error. This makes it obvious to the sender that the connection was blocked.

**Example:**
```
reject tcp any any -> any 21 (msg:"FTP connection rejected"; sid:1004; rev:1;)
```
This rule rejects any FTP connection attempts on port 21.

# Suricata Rule Actions: Additional Explanation on the `reject` Action

## Overview of the `reject` Action
In Suricata, the `reject` action is a blocking mechanism designed for Intrusion Prevention System (IPS) mode. Unlike the `pass` action, which explicitly allows traffic to bypass other rules, the `reject` action **does not permit the traffic to continue**. Instead, it actively intervenes to terminate the connection while providing feedback to the sender. This makes it particularly useful for scenarios where you want to not only block malicious or unwanted traffic but also notify the source that the attempt was detected and stopped.

### How the `reject` Action Works
- **Blocking Behavior**: When a packet matches a rule with the `reject` action, Suricata immediately drops the packet, preventing it from reaching its destination.
- **Response to Sender**: Suricata generates and sends a rejection response back to the originating device. The type of response depends on the protocol:
  - For **TCP connections**, it sends a **TCP reset (RST) packet**. A TCP reset is a special control packet that instructs both endpoints (sender and receiver) to abruptly close the connection. In simple terms, it tells the computers involved to "stop sending messages to each other" and reset the session, effectively ending any ongoing communication.
  - For **UDP or ICMP**, it may send an ICMP "port unreachable" or similar error message.
- **Alert Generation**: Like the `drop` action, `reject` also logs an alert in Suricata's event output (e.g., for analysis in tools like Eve JSON or a SIEM system), so you can review and investigate the blocked activity.
- **Key Difference from `drop`**: While `drop` silently discards the packet without notifying the sender (making the block "stealthy"), `reject` is more "noisy" because it sends an explicit rejection. This can deter attackers by revealing that their attempt was noticed, but it might also tip off sophisticated adversaries.

### Example of a `reject` Rule
Here's a practical example of a rule using the `reject` action to block FTP attempts (port 21), which is often insecure and should be restricted:

```
reject tcp any any -> any 21 (msg:"FTP connection rejected"; sid:1004; rev:1;)
```

- **What Happens**: If incoming TCP traffic targets port 21, Suricata drops the packet and sends a TCP RST to the client. The client will see the connection fail immediately, often with an error like "Connection reset by peer."
- **Use Case**: Ideal for legacy protocols like FTP or Telnet where you want to enforce policy by both blocking and signaling rejection, rather than letting the connection time out unnoticed.


# Suricata Rule Header

## Overview
In Suricata, the **header** is the core structural component of a rule (also known as a signature) that immediately follows the action keyword. It precisely defines the network traffic that the rule will inspect and match against. The header specifies key attributes of the traffic, including:
- **Protocol**: The type of network protocol (e.g., TCP, UDP, HTTP).
- **Source and Destination IP Addresses**: The originating (source) and target (destination) IP ranges or hosts.
- **Source and Destination Ports**: The ports involved in the communication (or "any" for all ports).
- **Traffic Direction**: The flow of traffic (e.g., from internal to external networks).

The header ensures that Suricata only evaluates the rule's conditions (like content matching or metadata) if the traffic fits these criteria. This makes rules efficient and targeted, reducing false positives and improving performance. Headers follow a standard format: `protocol source_ip source_port -> destination_ip destination_port`.

## The Protocol Field
The first field in the header, right after the action, is the **protocol**. This specifies the network layer protocol or application-layer protocol that the rule applies to. Suricata supports a wide range of protocols, such as `tcp`, `udp`, `icmp`, `http`, `dns`, `tls`, and more.

- **Example**: In a rule like `alert http ...`, the protocol is `http`. This means the rule only triggers on HTTP traffic (e.g., web requests over port 80 or 443). Suricata's protocol detection engine will inspect the traffic to confirm it's HTTP before applying the rule.
- **Why It Matters**: Limiting to a specific protocol focuses the rule on relevant traffic. For instance, an `http` rule won't waste resources checking FTP packets.
- **Common Protocols**:
  - Transport layer: `tcp`, `udp`, `icmp`.
  - Application layer: `http`, `https`, `ftp`, `ssh`, `smtp`.

If no protocol is specified, Suricata defaults to IP-level inspection, but it's best practice to always include one for precision.

## Source and Destination Specifications
After the protocol, the header defines the **source** (origin) and **destination** (target) details in the format: `source_ip source_port -> destination_ip destination_port`.

- **IP Addresses**: These can be specific IPs, CIDR ranges, or variables (explained below). They identify the networks or hosts involved.
- **Ports**: These specify the source and destination ports (e.g., `80` for HTTP). The keyword `any` (or `0`) means "match any port," making the rule broader.
- **Example Breakdown**: In `$HOME_NET any -> $EXTERNAL_NET any`:
  - **Source**: `$HOME_NET any` – Traffic originating from your internal network on any source port.
  - **Destination**: `$EXTERNAL_NET any` – Traffic heading to external (internet-facing) addresses on any destination port.

This setup is common for rules that monitor outbound traffic from your protected environment.

## Traffic Direction Indicator (`->`)
The arrow (`->`) explicitly denotes the **direction of traffic flow**:
- **Source -> Destination**: Traffic moving from the source (left side) to the destination (right side). This is the most common direction for rules monitoring inbound or outbound threats.
- **Bidirectional Rules**: For traffic in both directions, you can use `<>` (e.g., `$HOME_NET 80 <-> $EXTERNAL_NET any`), which matches flows regardless of initiation side. However, `->` is unidirectional and more precise for asymmetric traffic (e.g., client requests to servers).

Direction matters because network security often distinguishes between internal-to-external (e.g., data exfiltration) and external-to-internal (e.g., incoming attacks) flows.

## Variables in Suricata Rules (`$HOME_NET` and `$EXTERNAL_NET`)
Variables are placeholders defined in Suricata's configuration file (`/etc/suricata/suricata.yaml`) under the `vars` section. They allow rules to be portable and adaptable without hardcoding specific values. The `$` symbol prefixes all variables to indicate they are dynamic.

- **$HOME_NET**: Represents your local or "home" network—the protected internal environment. It acts as a shortcut for IP ranges belonging to your organization.
  - **Lab-Specific Definition**: In this lab activity, `$HOME_NET` is configured as your designated local subnet. This means rules using `$HOME_NET` will match traffic from or to devices in that range.
  - **Customization**: You can edit `suricata.yaml` to add or modify it, e.g.:
    ```
    vars:
      HOME_NET: [your_local_subnet]
    ```
- **$EXTERNAL_NET**: Typically defined as everything outside `$HOME_NET`, often as `!$HOME_NET` (meaning "not HOME_NET") or explicitly as public internet ranges (e.g., `any`). It represents external, untrusted networks.
  - **Default**: In many setups, it's `any` to catch all outbound/inbound traffic to the internet.
- **Other Common Variables**: `$EXTERNAL_NET`, `$HTTP_SERVERS`, `$DNS_SERVERS`. These make rules reusable across environments (e.g., different office subnets).

**Benefits of Variables**:
- **Flexibility**: Change the network definition once in the YAML file, and all rules update automatically.
- **Security**: Avoid exposing real IPs in shared rule sets (e.g., from Emerging Threats).

## Full Example of a Rule Header
Putting it together, here's a complete rule example using the concepts above:

```
alert http $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Suspicious HTTP request to external server"; sid:1005; rev:1;)
```

- **Action**: `alert` – Generates a log/alert.
- **Protocol**: `http` – Applies only to HTTP traffic.
- **Source**: `$HOME_NET any` – From internal network on any port.
- **Direction**: `->` – Outbound to external.
- **Destination**: `$EXTERNAL_NET 80` – To any external IP on port 80 (standard HTTP).
- **What It Does**: Alerts on HTTP requests from your internal network to external web servers, useful for detecting potential command-and-control traffic.

The many available rule options allow you to customize signatures with additional parameters. Configuring rule options helps narrow down network traffic so you can find exactly what you’re looking for. As in our example, rule options are typically enclosed in a pair of parentheses and separated by semicolons.

Let's further examine the rule options in our example:

The msg: option provides the alert text. In this case, the alert will print out the text “GET on wire”, which specifies why the alert was triggered.
The flow:established,to_server option determines that packets from the client to the server should be matched. (In this instance, a server is defined as the device responding to the initial SYN packet with a SYN-ACK packet.)
The content:"GET" option tells Suricata to look for the word GET in the content of the http.method portion of the packet.
The sid:12345 (signature ID) option is a unique numerical value that identifies the rule.
The rev:3 option indicates the signature's revision which is used to identify the signature's version. Here, the revision version is 3.
To summarize, this signature triggers an alert whenever Suricata observes the text GET as the HTTP method in an HTTP packet from the home network going to the external network.

Perfect — here’s your task explained clearly, step by step, all wrapped into a single `.md` block so you can copy it directly:

````markdown
# Task 2: Trigger a Custom Rule in Suricata

In this task, you will trigger a custom Suricata rule and then examine the alert logs that are generated.

---

## Step 1: Check the Suricata log folder
Before running Suricata, the log directory `/var/log/suricata` is empty.  
Command:
```bash
ls -l /var/log/suricata
````
<img width="716" height="57" alt="image" src="https://github.com/user-attachments/assets/1e0c5c68-5de6-40b0-94ff-723fe9e988aa" />

---

## Step 2: Run Suricata with custom rules and sample traffic

Use Suricata to process a packet capture file with your custom rules:

```bash
sudo suricata -r sample.pcap -S custom.rules -k none
```

Explanation of options:

* `-r sample.pcap` → uses the packet capture file to mimic network traffic.
* `-S custom.rules` → tells Suricata to use the rules defined in `custom.rules`.
* `-k none` → disables checksum checks (not needed for pre-recorded traffic).
<img width="936" height="290" alt="image" src="https://github.com/user-attachments/assets/06522c84-9fdc-4e67-b16e-b11619a7d7d1" />

When Suricata runs, it reports how many packets were processed.

---

## Step 3: Check the log folder again

After Suricata runs, the `/var/log/suricata` folder now contains multiple files.

<img width="757" height="168" alt="image" src="https://github.com/user-attachments/assets/63ecf897-c79e-40cd-b14d-011dd19a55c3" />


Key files to note:

* **fast.log** → contains a quick summary of triggered alerts.
* **eve.json** → contains detailed alerts and metadata in JSON format.

Command:

```bash
ls -l /var/log/suricata
```

---

## Step 4: View the alerts in fast.log

Display the contents of `fast.log`:

```bash
cat /var/log/suricata/fast.log
```

Example output shows that the custom rule was triggered, producing alert entries. Each alert line includes:

* A **timestamp** (when the alert was triggered).
* The **rule information** (for example, "GET on wire").
* **Classification** and **priority** of the alert.
* The **protocol used** (e.g., TCP).

---

## Key Point

Whenever traffic from the packet capture matches the conditions defined in your `custom.rules`, Suricata generates alerts and records them in `fast.log` (simple summary) and `eve.json` (detailed logs).



```markdown
# Task 3: Examine eve.json Output

In this task, you will examine the **eve.json** file generated by Suricata.  
This file contains detailed alert data in **JSON format** and is much richer than the simple `fast.log`.

---

## Step 1: Locate the eve.json file
The file is stored in:
```

/var/log/suricata/eve.json

````

---

## Step 2: Display the raw content
You can display the file with:
```bash
cat /var/log/suricata/eve.json
````

* This shows the full contents in raw JSON.
* However, it will look **messy and difficult to read** because JSON is not formatted nicely by default.

---

## Step 3: Format the output with jq

To make the JSON readable, use the `jq` command:

```bash
jq . /var/log/suricata/eve.json | less
```

* `jq .` → formats (pretty-prints) the JSON data.
* `| less` → lets you scroll through the output one screen at a time.

Here’s the explanation for the `jq` filtering with **flow_id**, written in a clean `.md` format so you can copy it directly:

````markdown
# Working with Suricata eve.json Using jq

The `eve.json` file generated by Suricata contains detailed JSON-formatted logs.  
Using the `jq` tool, you can extract and filter specific fields to make the data easier to analyze.

---

## Extract specific fields
Run the following command:
```bash
jq -c "[.timestamp,.flow_id,.alert.signature,.proto,.dest_ip]" /var/log/suricata/eve.json
````

### Explanation

* `jq -c` → compact output (keeps results on one line per event).
* `[ ... ]` → extracts only the listed fields from each JSON object.
* `.timestamp` → shows when the event happened.
* `.flow_id` → shows the unique ID assigned to the network flow.
* `.alert.signature` → shows the name or message of the rule that triggered.
* `.proto` → shows the protocol used (e.g., TCP, UDP).
* `.dest_ip` → shows the destination IP address.

Result: a simplified list of events with only the most relevant fields for quick scanning.

---

## Filter by a specific flow_id

Each network flow is assigned a unique 16-digit number called a `flow_id`.
To see all logs tied to a single flow, use:

```bash
jq "select(.flow_id==X)" /var/log/suricata/eve.json
```

Replace `X` with the actual flow_id number from the previous command.

### Why flow_id matters

* A **network flow** is a sequence of packets between a source and destination that share the same characteristics (IP, ports, protocol, etc.).
* Suricata uses `flow_id` to group all packets that belong to the same flow.
* By filtering on one `flow_id`, you can reconstruct and analyze the **entire conversation** between endpoints.

<img width="937" height="191" alt="image" src="https://github.com/user-attachments/assets/5944d9cb-7a29-4923-8d62-c225663d0bd0" />
