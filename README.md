# AnonymousChat

> AnonymousChat is a fully anonymous peer-to-peer chat application developed as part of the **CSE471 - Data Communications and Computer Networks** course at Yeditepe University.  
> It utilizes RSA encryption, subnet gateways, spoofed IP/MAC headers, and a custom overlay network for secure and anonymous communication across different networks.

---

## 🚀 Features

- 🔒 **End-to-end encryption** with RSA
- 🌐 **Peer-to-peer overlay network** design
- 📶 **Broadcast** communication within subnets
- 🛜 **Gateway peers** to relay between subnets
- 💻 **Graphical User Interface (GUI)** with Java Swing
- 🧠 **Public/private key generation** for every user
- 🔃 **Spoofed IP and MAC addresses** (via raw socket programming)
- 🧱 **Custom packet format & reassembly**
- 🔄 **Cycle prevention** and **broadcast storm control**
- 🧑‍🤝‍🧑 Real-time list of active users and public keys
- 🗃️ Multi-part message support
- 💬 [Bonus] Private chat feature
- 📁 [Bonus] Encrypted file transfer

---

## 🧱 System Architecture

- Java GUI + High-Level Networking Logic
- Python (Scapy) or C++ for low-level spoofing
- Overlay network composed of:
  - **Client Peers** – chat participants
  - **Gateway Peers** – routers/relays across subnets

---

## 🧪 Project Requirements 

- Manual mode switching: Client / Gateway
- RSA encryption & key management
- GUI menus: Generate Keys, Connect, Disconnect, Exit
- Encrypted & spoofed IP/MAC packets
- Gateway IP list management (local or remote)
- Packet reassembly logic for large messages
- Protocol for nickname/public key broadcasting
- Message flooding control via timers/TTL

---

## 🧰 Technologies Used

| Tech | Purpose |
|------|---------|
| Java | GUI and control logic |
| Python + Scapy / C++ | Raw socket handling and spoofing |
| RSA | Message encryption |
| UDP/TCP | Subnet relay communication |