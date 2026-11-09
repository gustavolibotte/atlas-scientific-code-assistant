export type CapabilityState = "available" | "demo_only" | "not_implemented";

export interface Capability {
  id: string;
  label: string;
  status: CapabilityState;
}

export interface Evidence {
  id: string;
  title: string;
  locator: string;
  authority: string;
  is_real_source: boolean;
}

export interface Trace {
  is_synthetic: boolean;
  disclaimer: string;
  decision: {
    id: string;
    statement: string;
    rationale: string;
    evidence_ids: string[];
    code_symbol_ids: string[];
    verification_ids: string[];
  };
  evidence: Evidence[];
  symbols: { id: string; qualified_name: string; file_path: string; revision: string }[];
  verifications: { id: string; label: string; state: string }[];
}

export interface SystemState {
  connected: boolean;
  version: string | null;
  capabilities: Capability[];
  trace: Trace | null;
  error: string | null;
}

async function getJson<T>(path: string, signal: AbortSignal): Promise<T> {
  const response = await fetch(path, { signal, credentials: "omit" });
  if (!response.ok) throw new Error(`HTTP ${response.status} for ${path}`);
  return (await response.json()) as T;
}

export async function getSystemState(signal: AbortSignal): Promise<SystemState> {
  try {
    const [ready, capabilities, trace] = await Promise.all([
      getJson<{ status: string; version: string }>("/api/v1/health/ready", signal),
      getJson<{ items: Capability[] }>("/api/v1/system/capabilities", signal),
      getJson<Trace>("/api/v1/demo/trace", signal),
    ]);
    if (ready.status !== "ready") throw new Error("API is not ready");
    return {
      connected: true,
      version: ready.version,
      capabilities: capabilities.items,
      trace,
      error: null,
    };
  } catch (error) {
    if (signal.aborted) throw error;
    return {
      connected: false,
      version: null,
      capabilities: [],
      trace: null,
      error: error instanceof Error ? error.message : "Unknown API error",
    };
  }
}
