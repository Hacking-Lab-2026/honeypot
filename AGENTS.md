# AGENTS.md

## Project Overview

This repository contains a research-oriented DDoS amplification honeypot framework written in Go.

The goal of the project is to study attacker behavior and amplification DDoS tactics by deploying configurable UDP amplification honeypots and collecting interaction data.

The system supports:
- Multiple honeypot protocols
- Configurable response behaviors
- Rate limiting strategies
- A/B testing between honeypot variants
- Event collection and analysis

This project is part of a research effort focused on understanding attacker tactics, techniques, and procedures (TTPs) in amplification DDoS attacks.

---

# Research Questions

## Main Research Question

How can honeypot design choices be systematically evaluated through A/B testing?

## Sub Questions

### SQ1
Do attackers interact more with honeypots that return larger responses, even if those responses are less realistic?

### SQ2
Do attackers behave differently toward hosts exposing one service versus multiple amplification services?

### SQ3
Which rate-limiting strategy reduces outgoing traffic the most while still preserving useful information about scans and probes?

### SQ4
Does the network where the honeypot is deployed influence how quickly it is discovered?

---

# Technical Requirements

- Language: Go
- Architecture: Clean Architecture
- Focus on modularity and replaceable components
- The codebase should remain easy to extend with new honeypot protocols and experimentation logic

---

# Architecture Principles

The repository follows Clean Architecture principles.

Dependency direction:

```text
Adapters → Usecases → Domain
```

I expect the following layers:
* usecases
* adapters
* ports
* models
* domain
* controller/handler