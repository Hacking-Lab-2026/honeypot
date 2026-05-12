# Architecture Documentation

## Clean Architecture Layers

This project implements Clean Architecture with the following dependency flow:

```
UDP Server Endpoint (adapters/servers)
    ↓
Handler/Controller (adapters/handlers)
    ↓
Usecase Layer (usecases)
    ↓
Domain Layer (domain)
    ↑
Ports/Interfaces (ports)
    ↑
Adapters (adapters)
```

## Request Flow Example

When a UDP probe arrives at the honeypot:

```
1. UDP Server Endpoint (udp_server.go)
   └─ Listens for incoming UDP packets
   
2. Handler/Controller (probe_handler.go)
   └─ Receives packet from endpoint
   └─ Extracts source IP, port, protocol, payload
   
3. Usecase (handle_probe.go)
   └─ Orchestrates business logic
   └─ Applies rate limiting (uses RateLimiter port/adapter)
   └─ Creates domain event via ProbeService
   └─ Persists event (uses EventRepository port/adapter)
   └─ Logs activities (uses Logger port/adapter)
   
4. Domain Services
   └─ ProcessProbe: Pure business logic for creating events
   
5. Adapters (Concrete Implementations)
   └─ ConsoleLogger: Logs to stdout
   └─ InMemoryEventRepository: Stores events in memory
   └─ NoOpRateLimiter: Allows all requests (demo implementation)
   
6. Response sent back to attacker
```

## Layer Descriptions

### Endpoint Layer (`internal/adapters/servers/`)

The outermost layer that interfaces with the outside world.

- **UDP Server** - Listens on a socket, receives incoming probes, routes to handler

### Handler/Controller Layer (`internal/adapters/handlers/`)

Bridges the endpoint and usecases. Unmarshals requests and passes data.

- **ProbeHandler** - Receives probe data, calls usecase, returns response

### Usecase Layer (`internal/usecases/probe/`)

Orchestrates business logic. Each usecase represents a specific workflow.

- **ProcessProbeUsecase** - Handles the probe processing workflow
  - Validates using rate limiter
  - Creates domain events
  - Persists events
  - Logs activities

### Domain Layer (`internal/domain/`)

Pure business logic, independent of frameworks.

- **Models** - `ProbeEvent` entity
- **Services** - `ProbeService` for event creation logic

### Port Layer (`internal/ports/`)

Defines interfaces (contracts) that adapters implement.

- `Logger` - For logging
- `EventRepository` - For persistence
- `RateLimiter` - For rate limiting

### Adapter Layer (`internal/adapters/`)

Implements the ports with concrete technologies.

- **logging/** - Console logger implementation
- **persistence/** - In-memory event storage
- **ratelimit/** - No-op rate limiter
- **handlers/** - Request handlers
- **servers/** - Protocol-specific servers (UDP, etc.)

## Design Principles

- **Dependency Inversion**: Depend on abstractions (ports), not concrete implementations
- **Single Responsibility**: Each component has one reason to change
- **Open/Closed**: Easy to extend (new adapters) without modifying existing code
- **Interface Segregation**: Small, focused interfaces

## Adding New Features

To add a new feature (e.g., a new rate limiting strategy):

1. Create the implementation in `adapters/ratelimit/token_bucket_limiter.go`
2. Ensure it implements the `RateLimiter` port
3. Update `internal/app/application.go` to use the new implementation
4. Existing code remains unchanged - this is the power of the architecture

## Adding New Protocols

To add a new protocol (e.g., DNS honeypot):

1. Create a new server in `adapters/servers/dns_server.go`
2. Create a new usecase in `usecases/dns/handle_dns_query.go`
3. Create new handler in `adapters/handlers/dns_handler.go`
4. Update `internal/app/application.go` to wire the new protocol
5. Domain services and models can be reused across protocols
