/**
 * PORTS — the consumer injects an adapter for each. Adapters MAY be CF-specific;
 * the core never knows. Verbatim shapes from docs/FROZEN_CONTRACT.ts (section 3).
 *
 * No implementations live here — only the interfaces the hexagonal core depends
 * on. Built-in default impls (defaultCodeGenerator, systemClock) live in
 * ./crypto and ./util; optional CF/test adapters live in ./adapters.
 */
export {};
//# sourceMappingURL=ports.js.map