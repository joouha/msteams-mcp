/**
 * Tool registry - centralised tool management.
 *
 * All tools are registered here and can be looked up by name.
 * Account selection is process-scoped via TEAMS_MCP_ACCOUNT; account is not
 * exposed as an MCP tool parameter.
 */

import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import type { z } from 'zod';
import type { ToolResult } from './index.js';
import { ErrorCode, createError } from '../types/errors.js';

/** Type-erased tool entry for the registry — avoids generic variance issues. */
interface RegistryEntry {
  definition: Tool;
  schema: z.ZodTypeAny;
  handler: (input: z.output<z.ZodTypeAny>) => Promise<ToolResult>;
}

import { searchTools } from './search-tools.js';
import { messageTools } from './message-tools.js';
import { peopleTools } from './people-tools.js';
import { authTools } from './auth-tools.js';
import { meetingTools } from './meeting-tools.js';
import { fileTools } from './file-tools.js';
import { tagTools } from './tag-tools.js';
import { assignmentTools } from './assignment-tools.js';

const allTools: RegistryEntry[] = [
  ...searchTools,
  ...messageTools,
  ...peopleTools,
  ...authTools,
  ...meetingTools,
  ...fileTools,
  ...tagTools,
  ...assignmentTools,
];

const toolsByName = new Map<string, RegistryEntry>(
  allTools.map(tool => [tool.definition.name, tool])
);

export function getToolDefinitions(): Tool[] {
  return allTools.map(tool => tool.definition);
}

export function getTool(name: string): RegistryEntry | undefined {
  return toolsByName.get(name);
}

export async function invokeTool(name: string, args: unknown): Promise<ToolResult> {
  const tool = toolsByName.get(name);

  if (!tool) {
    return {
      success: false,
      error: createError(ErrorCode.INVALID_INPUT, `Unknown tool: ${name}`, { retryable: false }),
    };
  }

  const parseResult = tool.schema.safeParse(args);
  if (!parseResult.success) {
    return {
      success: false,
      error: createError(ErrorCode.INVALID_INPUT, `Invalid input: ${parseResult.error.message}`, { retryable: false }),
    };
  }

  return tool.handler(parseResult.data);
}

export function hasTool(name: string): boolean {
  return toolsByName.has(name);
}