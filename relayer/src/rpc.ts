// One JSON-RPC transport for both chains. Tests replace it with a fake.

export type Rpc = (method: string, params: unknown) => Promise<any>;

export function httpRpc(url: string): Rpc {
  return async (method, params) => {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    const body = (await res.json()) as any;
    if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
    return body.result;
  };
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
