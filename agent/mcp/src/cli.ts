import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createBuyerFromEnv } from './runtime.ts';
import { createServer } from './server.ts';
import { safeDetail } from './buyer.ts';

try {
  const buyer = await createBuyerFromEnv();
  const server = createServer(buyer);
  await server.connect(new StdioServerTransport());
  let checking = false;
  const timer = setInterval(() => {
    if (checking) return;
    checking = true;
    buyer.processDecisions().catch(error => {
      process.stderr.write(`Held decision processing failed: ${safeDetail(error)}\n`);
    }).finally(() => { checking = false; });
  }, 2000);
  server.server.onclose = () => { clearInterval(timer); };
} catch (error) {
  process.stderr.write(`Buyer MCP startup failed: ${safeDetail(error)}\n`);
  process.exitCode = 1;
}
