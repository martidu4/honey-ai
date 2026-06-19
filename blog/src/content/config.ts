import { z, defineCollection } from 'astro:content';

const reports = defineCollection({
  type: 'content',
  schema: z.object({
    date: z.coerce.date(),
    cowrie_connections: z.number().default(0),
    cowrie_logins: z.number().default(0),
    cowrie_commands: z.number().default(0),
    cowrie_ips: z.number().default(0),
    opencanary_events: z.number().default(0),
    opencanary_ips: z.number().default(0),
    top_ips: z.array(z.string()).default([]),
    top_commands: z.array(z.string()).default([]),
    top_passwords: z.array(z.string()).default([]),
    abuseipdb_reported: z.number().default(0),
    severity: z.enum(['quiet', 'low', 'medium', 'high', 'critical']).default('low'),
    // Galah LLM HTTP Honeypot (optional — only in reports from 2026-04-25 onwards)
    galah_requests: z.number().default(0),
    galah_ips: z.number().default(0),
    galah_top_paths: z.array(z.string()).default([]),
    galah_top_agents: z.array(z.string()).default([]),
    // 🤣 Attacker Comedy Corner (optional — extracted from Cowrie logs)
    funny_passwords: z.array(z.string()).default([]),
    funny_commands: z.array(z.string()).default([]),
    honeypot_files_accessed: z.array(z.string()).default([]),
    // 💥 Operation Spine (Reverse scans - backfire module)
    backfire_scans: z.number().default(0),
    backfire_ips: z.number().default(0),
    backfire_ports_tally: z.array(z.object({
      port: z.number(),
      count: z.number()
    })).default([]),
    backfire_targets: z.array(z.object({
      ip: z.string(),
      ports: z.array(z.number()),
      time: z.string().optional(),
      rdns: z.string().optional()
    })).default([]),
  }),
});

// AI-generated threat analysis blog posts
const blog = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    date: z.coerce.date(),
    description: z.string().default(''),
    severity: z.enum(['quiet', 'low', 'medium', 'high', 'critical']).default('medium'),
    tags: z.array(z.string()).default([]),
    total_ips: z.number().default(0),
    total_events: z.number().default(0),
    ai_model: z.string().default('qwen2.5:1.5b'),
    report_date: z.string().default(''),  // links back to the data report
  }),
});

export const collections = { reports, blog };
