# DDoS Honeypot Framework

A research-oriented DDoS amplification honeypot framework written in Go, designed to study attacker behavior and amplification DDoS tactics.

## Project Overview

This framework enables systematic evaluation of honeypot design choices through A/B testing. It provides:

- **Multiple honeypot protocols** - Support for various UDP amplification services
- **Configurable response behaviors** - Experiment with different honeypot variants
- **Rate limiting strategies** - Test and compare different traffic control approaches
- **Event collection and analysis** - Track and analyze attacker interactions
- **A/B testing framework** - Systematically evaluate honeypot effectiveness

## Research Goals

The project investigates critical questions about honeypot effectiveness:

1. **Response size impact**: Do attackers interact more with honeypots that return larger responses?
2. **Service diversity**: How does exposing multiple services affect attacker behavior?
3. **Rate limiting strategies**: Which approach reduces outgoing traffic while preserving insight?
4. **Network influence**: Does deployment location affect discovery speed?

## Architecture

This project follows **Clean Architecture** principles:

```
Adapters → Usecases → Domain
```

### Layer Structure

- **cmd/** - Application entry points
- **internal/domain/** - Core business logic and domain models
  - `models/` - Domain entities
  - `services/` - Business logic
- **internal/usecases/** - Application logic orchestrating domain components
- **internal/ports/** - Interface definitions for adapters
- **internal/adapters/** - External service implementations
  - `handlers/` - Request handlers
  - `logging/` - Logging implementations
  - `persistence/` - Data storage implementations
  - `ratelimit/` - Rate limiting implementations
- **internal/app/** - Application setup and dependency injection
- **docs/** - Documentation

## Getting Started

### Prerequisites

- Go 1.21 or higher

### Building

```bash
go build -o honeypot ./cmd/server
```

### Running

```bash
./honeypot
```

## Development

The project structure is designed to be modular and extensible. When adding new features:

1. Define domain models and services in `internal/domain/`
2. Create ports (interfaces) in `internal/ports/`
3. Implement adapters in `internal/adapters/`
4. Wire everything together in `internal/app/`
5. Use from entry points in `cmd/`

## License

Part of the Hacking-Lab research initiative.