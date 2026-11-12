// A slow-loris client for the server tests (PayPal audit 2 M1/M2).
import { connect } from "node:net";

/** Sends `head` and then one body byte every `everyMs`; resolves with what the server answered and when it closed. */
export function trickle(port: number, head: string, everyMs: number): Promise<{ answer: string; ms: number }> {
  return new Promise((done) => {
    const start = Date.now();
    let answer = "";
    // Queue the head before the first drip: a drip that fired before `connect` would otherwise go first.
    const c = connect(port, "127.0.0.1");
    c.write(head);
    const drip = setInterval(() => c.writable && c.write("x"), everyMs);
    c.on("data", (b) => (answer += b));
    c.on("close", () => (clearInterval(drip), done({ answer, ms: Date.now() - start })));
    c.on("error", () => {});
  });
}
