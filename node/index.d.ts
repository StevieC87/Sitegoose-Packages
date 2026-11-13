import type { IncomingMessage } from "node:http";

export interface ServerErrorEvent {
  message: string;
  error_type: string;
  stack: string;
  kind: "error" | "rejection" | "handled";
  status_code: number;
  runtime: string;
  runtime_version: string;
  os: string;
  server_name: string;
  method?: string;
  path?: string;
  route?: string;
  session_id?: string;
}

export interface InitOptions {
  siteId: string;
  secret: string;
  endpoint: string;
  serverName?: string;
  root?: string;
  captureUncaught?: boolean;
  beforeSend?: (event: ServerErrorEvent, error: unknown) => ServerErrorEvent | null;
  debug?: boolean;
}

export interface CaptureContext {
  req?: IncomingMessage;
  status?: number;
  kind?: "error" | "rejection" | "handled";
}

export function initServerErrors(options: InitOptions): void;
export function captureException(error: unknown, context?: CaptureContext): void;
export function errorHandler(options?: { shouldCapture?: (error: unknown, req: IncomingMessage) => boolean }):
  (error: unknown, req: IncomingMessage, res: unknown, next: (error?: unknown) => void) => void;
export function flush(): Promise<void>;
