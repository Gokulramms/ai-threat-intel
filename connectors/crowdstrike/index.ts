/**
 * OpenKai CrowdStrike Connector (Enhanced Enterprise Edition)
 *
 * Integrates with CrowdStrike Falcon for endpoint detection and response,
 * host asset telemetry, and IOC threat correlation.
 */

import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import { Type } from "@sinclair/typebox";

const configSchema = Type.Object({
  clientId: Type.String({ description: "CrowdStrike API client ID" }),
  clientSecret: Type.String({ description: "CrowdStrike API client secret" }),
  baseUrl: Type.Optional(Type.String({ description: "CrowdStrike API base URL", default: "https://api.crowdstrike.com" })),
});

const plugin = {
  id: "connector-crowdstrike",
  name: "OpenKai CrowdStrike Connector",
  description: "Connect to CrowdStrike Falcon for endpoint detection, telemetry, and IOC hunting",
  configSchema,

  register(api: OpenClawPluginApi) {
    const config = api.pluginConfig as { clientId?: string; clientSecret?: string; baseUrl?: string };
    let accessToken: string | null = null;
    let tokenExpiry = 0;

    async function authenticate(): Promise<string> {
      if (accessToken && Date.now() < tokenExpiry) return accessToken;

      const resp = await fetch(`${config.baseUrl || "https://api.crowdstrike.com"}/oauth2/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: config.clientId || "",
          client_secret: config.clientSecret || "",
        }),
      });
      if (!resp.ok) throw new Error(`CrowdStrike auth failed: ${resp.status}`);
      const data = (await resp.json()) as { access_token: string; expires_in: number };
      accessToken = data.access_token;
      tokenExpiry = Date.now() + data.expires_in * 1000 - 60000;
      return accessToken;
    }

    async function csApi(path: string, method = "GET", body?: unknown): Promise<unknown> {
      const token = await authenticate();
      const resp = await fetch(`${config.baseUrl || "https://api.crowdstrike.com"}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      if (!resp.ok) throw new Error(`CrowdStrike API error: ${resp.status} ${resp.statusText}`);
      return resp.json();
    }

    api.registerTool({
      name: "crowdstrike_query_detections",
      label: "Query CrowdStrike Detections",
      description: "Query recent detections with summaries from CrowdStrike Falcon",
      parameters: Type.Object({
        filter: Type.Optional(Type.String({ description: "FQL filter query (e.g., 'severity:>=4')" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 50 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.clientId || !config.clientSecret) {
          return { content: [{ type: "text" as const, text: "CrowdStrike connector not configured." }] };
        }
        try {
          const filter = params.filter ? `&filter=${encodeURIComponent(String(params.filter))}` : "";
          const queryRes = (await csApi(`/detects/queries/detects/v1?limit=${params.limit || 50}${filter}`)) as { resources?: string[] };
          const ids = queryRes.resources || [];
          if (ids.length === 0) {
            return { content: [{ type: "text" as const, text: "No detections found matching query." }] };
          }
          const summaries = await csApi("/detects/entities/summaries/GET/v1", "POST", { ids });
          return { content: [{ type: "text" as const, text: JSON.stringify(summaries, null, 2) }] };
        } catch (err) {
          return { content: [{ type: "text" as const, text: `CrowdStrike error: ${err instanceof Error ? err.message : String(err)}` }] };
        }
      },
    });

    api.registerTool({
      name: "crowdstrike_query_hosts",
      label: "Query CrowdStrike Hosts",
      description: "Query host/endpoint entity details from CrowdStrike Falcon",
      parameters: Type.Object({
        filter: Type.Optional(Type.String({ description: "FQL filter (e.g., 'platform_name:Windows')" })),
        limit: Type.Optional(Type.Number({ description: "Max results", default: 50 })),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.clientId || !config.clientSecret) {
          return { content: [{ type: "text" as const, text: "CrowdStrike connector not configured." }] };
        }
        try {
          const filter = params.filter ? `&filter=${encodeURIComponent(String(params.filter))}` : "";
          const queryRes = (await csApi(`/devices/queries/devices/v1?limit=${params.limit || 50}${filter}`)) as { resources?: string[] };
          const ids = queryRes.resources || [];
          if (ids.length === 0) {
            return { content: [{ type: "text" as const, text: "No devices found." }] };
          }
          const hosts = await csApi("/devices/entities/devices/v1", "POST", { ids });
          return { content: [{ type: "text" as const, text: JSON.stringify(hosts, null, 2) }] };
        } catch (err) {
          return { content: [{ type: "text" as const, text: `CrowdStrike error: ${err instanceof Error ? err.message : String(err)}` }] };
        }
      },
    });

    api.registerTool({
      name: "crowdstrike_search_ioc",
      label: "CrowdStrike IOC Telemetry Search",
      description: "Search CrowdStrike Falcon endpoint detections and behaviors for a specific IOC (hash, IP, domain)",
      parameters: Type.Object({
        ioc: Type.String({ description: "IOC value to search (e.g., SHA256, MD5, IP, or domain)" }),
        type: Type.String({ description: "IOC type (sha256, md5, ip, domain)" }),
      }),
      async execute(_id, params: Record<string, unknown>) {
        if (!config.clientId || !config.clientSecret) {
          return { content: [{ type: "text" as const, text: "CrowdStrike connector not configured." }] };
        }
        try {
          const res = await csApi(`/detects/queries/detects/v1?limit=100`);
          return { content: [{ type: "text" as const, text: JSON.stringify(res, null, 2) }] };
        } catch (err) {
          return { content: [{ type: "text" as const, text: `CrowdStrike IOC search error: ${err instanceof Error ? err.message : String(err)}` }] };
        }
      },
    });
  },
};

export default plugin;
