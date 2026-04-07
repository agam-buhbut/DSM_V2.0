DSM_V2.0

Open-source, anonymity and security first VPN designed to run on any Linux machine.

GOAL
Provide a highly secure, anonymity-preserving VPN tunnel resistant to ISP surveillance, DPI, traffic analysis, and active adversaries.

NON-GOALS
- Multiple endpoints
- Server hopping
- Geographic location switching
- Large-scale multi-user infrastructure

ARCHITECTURE

Flow:
Client -> Optional Relay(s) -> Client-Owned Server -> Destination

Components:
- Client
- Relay server(s) (optional, forwarding only)
- Client-owned server

Roles:
Client:
- Performs encryption
- Generates chaff traffic
- Applies padding and timing randomization

Relay:
- Forwards traffic only
- Does not decrypt or inspect packets

Server:
- Handles handshake and key exchange
- Reduces client computational load

State Model:
- Session-based
- Finite State Machine (6 steps)

NETWORKING

Transport:
- UDP (default)
- TCP/SFTP (fallback)

Streams:
- Multiple streams supported
- Designed for ~3–4 concurrent clients

Reliability:
- Built-in retransmission
- Fragmentation handled

CRYPTOGRAPHY

Key Exchange:
- Noise XX pattern
- Static key caching for faster re-authentication while maintaining anonymity

Key Lifecycle:
- Rotation every 5000 packets or 10 minutes (atomic)

Encryption:
- AES-256-GCM (AEAD)
- No separate HMAC

Nonce Strategy:
- Random nonces with enforced uniqueness

Replay Protection:
- 64-bit sliding window

Key Storage:
- Memory locked (mlock)
- Keys overwritten multiple times before destruction
- Implemented in Rust for memory safety and zeroization

ANONYMITY AND TRAFFIC RESISTANCE

Traffic Shaping:
- Aggressive and random padding
- Chaff (fake packets)
- Variable packet sizes

Timing:
- Randomized intervals (jitter)

Fingerprinting Resistance:
- Obfuscation on client side
- Minimize identifiable protocol patterns
- Hide device and destination details where possible

DNS:
- Resolved on server side
- Recursive DNS provider with caching
- Offline resolution supported
- Multiple provider switching (recursive + 2 custom)

Connection Behavior:
- Session-based
- Designed for maximum anonymity and authentication security

THREAT MODEL

Adversaries:
- ISP surveillance
- DPI systems
- Active MITM attackers
- State-level adversaries
- Hostile/unsecured WiFi networks

Assumptions:
- Network is hostile
- Server is trusted
- Client is untrusted

Out of Scope:
- Physical access to client/server
- Compromised dependencies or libraries

IMPLEMENTATION

Languages:
- Python (primary)
- Rust (key management, memory locking, zeroization)

Concurrency:
- Implementation-dependent

Error Handling:
- Limited retry logic to reduce DoS risk

CONFIGURATION

Configuration Method:
- Config files (.py and .rs) located in /opt

Configurable Parameters:
- Server IP
- Port

SETUP

File Placement:
- nftables config: nftables/nftables.conf
- Python/Rust code: /opt/mtun

Dependencies:
- Noise framework
- nftables
- Additional dependencies defined by developer

BUILD AND RUN
- To be defined

SECURITY NOTES
- To be defined

LOGGING

Development:
- Full verbose logging

Production:
- Errors and warnings only

PERFORMANCE

Target:
- 3–4 clients
- Everyday usage

Bottlenecks:
- Client-side encryption performance
- Network conditions

Optimizations:
- Implementation-dependent

TESTING

- Unit and feature-level testing suites
- Real-world testing with live clients
- Focus on correctness and standard adherence

FUTURE WORK
- To be defined

ADDITIONAL NOTES
- To be defined
