import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";

const payloads: Record<string, unknown> = {
  "/api/v1/health/ready": { status: "ready", version: "0.1.0" },
  "/api/v1/system/capabilities": {
    items: [
      { id: "foundation_api", label: "Foundation API", status: "available" },
      { id: "chatlas", label: "chATLAS retrieval", status: "not_implemented" },
    ],
  },
  "/api/v1/demo/trace": {
    is_synthetic: true,
    disclaimer: "Synthetic UI demonstration; no CERN source, code, or test was consulted.",
    decision: { id: "d1", statement: "Synthetic decision", rationale: "No real science", evidence_ids: ["e1"], code_symbol_ids: ["s1"], verification_ids: ["v1"] },
    evidence: [{ id: "e1", title: "Synthetic source", locator: "synthetic:demo", authority: "unverified", is_real_source: false }],
    symbols: [{ id: "s1", qualified_name: "demo_function", file_path: "example.py", revision: "demo" }],
    verifications: [{ id: "v1", label: "Not executed", state: "not_run" }],
  },
};

function mockApi(): void {
  vi.stubGlobal("fetch", vi.fn(async (path: string) => ({ ok: true, json: async () => payloads[path] })));
}

beforeEach(() => mockApi());
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("foundation workspace", () => {
  it("shows real API connection and accurate capability counts", async () => {
    render(<App />);
    expect(await screen.findByText("API connected")).toBeInTheDocument();
    expect(screen.getByText("1 / 2")).toBeInTheDocument();
    expect(screen.getByText("Demo only")).toBeInTheDocument();
  });

  it("navigates to provenance and never presents mock evidence as real", async () => {
    render(<App />);
    await screen.findByText("API connected");
    fireEvent.click(screen.getByRole("button", { name: /Evidence/ }));
    expect(screen.getByText("Synthetic decision")).toBeInTheDocument();
    expect(screen.getByText(/no CERN source, code, or test was consulted/i)).toBeInTheDocument();
    expect(screen.getByText("Not executed")).toBeInTheDocument();
  });

  it("previews a request without sending it to a model", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /Workspace/ }));
    const prompt = screen.getByRole("textbox", { name: /Describe a scientific coding task/ });
    fireEvent.change(prompt, { target: { value: "Compare estimators" } });
    fireEvent.click(screen.getByRole("button", { name: /Preview draft/ }));
    expect(screen.getByText("Compare estimators")).toBeInTheDocument();
    expect(screen.getByText(/No code was generated/)).toBeInTheDocument();
  });

  it("fails transparently if backend cannot be reached", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("offline"); }));
    render(<App />);
    await waitFor(() => expect(screen.getByText("API offline")).toBeInTheDocument());
    expect(screen.getByRole("status")).toHaveTextContent("Backend disconnected");
  });
});
