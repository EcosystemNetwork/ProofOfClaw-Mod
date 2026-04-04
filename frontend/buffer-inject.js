// Injected BEFORE any other module code by esbuild --inject flag
// This ensures Buffer is globally available when @ledgerhq/* modules initialize
import { Buffer } from 'buffer';
globalThis.Buffer = Buffer;
