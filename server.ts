import express, { Request, Response } from "express"
import cors from "cors"
import dotenv from "dotenv"
import fetch from "node-fetch"
import session from 'express-session'
import * as crypto from 'crypto'
import { URLSearchParams } from 'url'

dotenv.config()

// Extend session interface to include our custom properties
declare module 'express-session' {
  interface SessionData {
    tenantId?: string;
    account?: {
      oid: string;
      upn?: string;
      name?: string;
    };
    codeVerifier?: string;
  }
}

const app = express()
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: false }))

// WARNING: For production use a secure session store (Redis, DB) and secure cookie settings.
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}))

const PORT = Number(process.env.PORT || process.env.API_PORT || 4000)

// ============ JIRA Configuration ============
const DOMAIN = process.env.JIRA_DOMAIN
const EMAIL = process.env.JIRA_EMAIL
const API_TOKEN = process.env.JIRA_API_TOKEN
const PROJECT_KEY = process.env.JIRA_PROJECT_KEY
const TEAM_FIELD = process.env.JIRA_TEAM_FIELD_ID // Optional custom field key, e.g. customfield_12345

let auth = ''
if (EMAIL && API_TOKEN) {
  auth = Buffer.from(`${EMAIL}:${API_TOKEN}`).toString("base64")
  console.log('[Jira] Auth configured for email:', EMAIL)
}

const MS_PER_DAY = 1000 * 60 * 60 * 24

const isJiraConfigReady = DOMAIN && EMAIL && API_TOKEN && PROJECT_KEY
if (!isJiraConfigReady) {
  console.warn("[Jira] Configuration incomplete:", { domain: !!DOMAIN, email: !!EMAIL, token: !!API_TOKEN, projectKey: !!PROJECT_KEY })
}

// ============ ASANA Configuration ============
const ASANA_TOKEN = process.env.ASANA_TOKEN
const DEFAULT_ASANA_PROJECT_ID = process.env.ASANA_PROJECT_ID
const ASANA_BASE_URL = "https://app.asana.com/api/1.0"
const IMPORTED_ASSIGNEE_FIELD_GID = "1212641939726131"

const isAsanaConfigReady = !!ASANA_TOKEN
if (!isAsanaConfigReady) {
  console.warn("Asana API is not fully configured. Please set ASANA_TOKEN in your .env file.")
}

// ============ Microsoft 365 Configuration ============
const CLIENT_ID: string = process.env.CLIENT_ID || '';
const CLIENT_SECRET: string = process.env.CLIENT_SECRET || '';
const REDIRECT_URI: string = process.env.REDIRECT_URI || 'http://localhost:4000/auth/callback';
const AUTHORIZE_URL: string = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
const TOKEN_URL: string = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
const GRAPH_BASE: string = 'https://graph.microsoft.com/v1.0';

// Scopes requested (delegated). Admin consent is required for some permissions.
const SCOPES: string = [
  'offline_access',
  'openid',
  'profile',
  'User.Read',
  'Calendars.Read',
  'Channel.ReadBasic.All',
  'ChannelMessage.Read.All',
  'Chat.Read',
  'OnlineMeetings.Read',
  'Team.ReadBasic.All'
].join(' ');

// Type definitions
interface PKCE {
  codeVerifier: string;
  codeChallenge: string;
}

interface TokenStore {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  tenantId: string | null;
  account: {
    oid: string;
    upn?: string;
    name?: string;
  } | null;
}

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  scope: string;
  token_type: string;
  id_token?: string;
}

const isMicrosoftConfigReady = CLIENT_ID && CLIENT_SECRET
if (!isMicrosoftConfigReady) {
  console.warn("[Microsoft 365] Configuration incomplete:", { clientId: !!CLIENT_ID, clientSecret: !!CLIENT_SECRET })
}

const extractDescription = (desc: any): string => {
  if (!desc) return ""
  if (typeof desc === "string") return desc
  if (Array.isArray(desc)) return desc.join(" ")
  if (desc.content) {
    const parts: string[] = []
    const walk = (nodes: any[]): void => {
      nodes.forEach((node: any) => {
        if (node.text) parts.push(node.text)
        if (node.content) walk(node.content)
      })
    }
    walk(desc.content)
    return parts.join(" ").trim()
  }
  return ""
}

// Auth functions
function generatePKCE(): PKCE {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const hash = crypto.createHash('sha256').update(codeVerifier).digest();
  const codeChallenge = hash.toString('base64url');
  return { codeVerifier, codeChallenge };
}

async function exchangeCodeForTokens(code: string, codeVerifier: string): Promise<TokenResponse> {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    code,
    code_verifier: codeVerifier,
    grant_type: 'authorization_code',
    redirect_uri: REDIRECT_URI,
    scope: SCOPES
  });

  const response = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed: ${response.status} ${response.statusText}`);
  }

  return response.json() as Promise<TokenResponse>;
}

async function refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token: refreshToken,
    grant_type: 'refresh_token',
    scope: SCOPES
  });

  const response = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  });

  if (!response.ok) {
    throw new Error(`Token refresh failed: ${response.status} ${response.statusText}`);
  }

  return response.json() as Promise<TokenResponse>;
}

async function ensureValidAccessTokenForSession(req: Request): Promise<string> {
  const session = req.session as any;
  if (!session.tokens) {
    throw new Error('No tokens in session');
  }

  const now = Date.now();
  if (session.tokens.expiresAt > now + 60000) { // 1 minute buffer
    return session.tokens.accessToken;
  }

  // Refresh token
  const tokenResponse = await refreshAccessToken(session.tokens.refreshToken);
  session.tokens.accessToken = tokenResponse.access_token;
  session.tokens.refreshToken = tokenResponse.refresh_token || session.tokens.refreshToken;
  session.tokens.expiresAt = now + (tokenResponse.expires_in * 1000);
  return session.tokens.accessToken;
}

// Graph functions
interface CallGraphOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: any;
}

async function callGraph(req: Request, path: string, opts: CallGraphOptions = {}): Promise<any> {
  const accessToken = await ensureValidAccessTokenForSession(req);
  const url = path.startsWith('http') ? path : `${GRAPH_BASE}${path}`;
  const res = await fetch(url, {
    method: opts.method || 'GET',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      ...(opts.headers || {})
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });

  if (!res.ok) {
    const text = await res.text();
    const err = new Error(`Graph API error ${res.status}: ${text}`) as any;
    err.status = res.status;
    throw err;
  }
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch (jsonErr) {
      throw new Error(`Invalid JSON response from Graph API: ${(jsonErr as Error).message}. Response: ${text.substring(0, 500)}...`);
    }
  }
  return res.text();
}

async function getMe(req: Request): Promise<any> {
  return callGraph(req, '/me');
}

async function getUsers(req: Request): Promise<any> {
  return callGraph(req, '/users?$select=id,displayName');
}

async function getUserCalendarEvents(req: Request, userId: string, start: string, end: string): Promise<any> {
  const url = `/users/${userId}/calendarView?startDateTime=${encodeURIComponent(start)}&endDateTime=${encodeURIComponent(end)}&$select=subject,start,end,attendees`;
  return callGraph(req, url);
}

async function getOnlineMeetings(req: Request): Promise<any> {
  return callGraph(req, '/me/onlineMeetings');
}

async function getChats(req: Request): Promise<any> {
  return callGraph(req, '/me/chats');
}

async function getChatMessages(req: Request, chatId: string): Promise<any> {
  return callGraph(req, `/chats/${chatId}/messages`);
}

async function getEmailActivityReport(req: Request, period: string = 'D30'): Promise<any> {
  const path = `https://graph.microsoft.com/v1.0/reports/getEmailActivityUserDetail(period='${period}')`;
  return callGraph(req, path, { method: 'GET' });
}

// Auth routes
app.get('/auth/login', (req: Request, res: Response) => {
  const pkce = generatePKCE();
  (req.session as any).codeVerifier = pkce.codeVerifier;

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: 'code',
    redirect_uri: REDIRECT_URI,
    scope: SCOPES,
    code_challenge: pkce.codeChallenge,
    code_challenge_method: 'S256',
    state: crypto.randomBytes(16).toString('hex')
  });

  res.redirect(`${AUTHORIZE_URL}?${params}`);
});

app.get('/auth/callback', async (req: Request, res: Response) => {
  const { code, state } = req.query as { code?: string; state?: string };
  const codeVerifier = (req.session as any).codeVerifier;

  if (!code || !codeVerifier) {
    return res.status(400).send('Missing code or code verifier');
  }

  try {
    const tokenResponse = await exchangeCodeForTokens(code, codeVerifier);
    const now = Date.now();

    (req.session as any).tokens = {
      accessToken: tokenResponse.access_token,
      refreshToken: tokenResponse.refresh_token,
      expiresAt: now + (tokenResponse.expires_in * 1000),
      tenantId: null,
      account: null
    };

    // Get user info
    const me = await callGraph(req, '/me');
    (req.session as any).tokens.account = {
      oid: me.id,
      upn: me.userPrincipalName,
      name: me.displayName
    };

    res.redirect('/'); // Redirect to frontend
  } catch (err: any) {
    console.error('Auth callback error:', err);
    res.status(500).send('Authentication failed');
  }
});

app.post('/auth/logout', (req: Request, res: Response) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Session destroy error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ message: 'Logged out' });
  });
});

app.get('/auth/status', (req: Request, res: Response) => {
  const session = req.session as any;
  const authenticated = !!(session?.tokens?.account);
  res.json({
    authenticated,
    account: authenticated ? session.tokens.account : null
  });
});

// ============ ASANA API Endpoints ============
app.get("/api/asana/issues", async (req: Request, res: Response) => {
  // Get project ID from query parameter or use default from env
  const projectId = (req.query.projectKey as string) || DEFAULT_ASANA_PROJECT_ID

  if (!projectId) {
    return res.status(400).json({ error: "Project ID is required. Provide it as ?projectKey=YOUR_PROJECT_ID or set ASANA_PROJECT_ID in .env" })
  }

  if (!isAsanaConfigReady) {
    return res.status(500).json({ error: "Asana configuration missing - ASANA_TOKEN not set" })
  }

  try {
    const response = await fetch(
      `${ASANA_BASE_URL}/tasks?project=${projectId}&opt_fields=name,completed,assignee.name,start_on,due_on,memberships.section.name,notes,custom_fields,custom_fields.enum_value,custom_fields.enum_value.name`,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${ASANA_TOKEN}`,
          Accept: "application/json",
        },
      }
    )

    if (!response.ok) {
      const message = await response.text()
      return res.status(response.status).json({ error: "Failed to fetch Asana tasks", details: message })
    }

    const data = await response.json() as any
    const tasks = (data.data || []).map((task: any) => {
      const startDate = task.start_on || null
      const due = task.due_on || null
      
      // Calculate duration from start_on to due_on (inclusive of both start and end dates)
      const duration = startDate && due 
        ? Math.ceil((new Date(due).getTime() - new Date(startDate).getTime()) / MS_PER_DAY) + 1
        : ""

      // Get imported assignee from custom field
      const importedAssigneeField = task.custom_fields?.find(
        (cf: any) => cf.gid === IMPORTED_ASSIGNEE_FIELD_GID
      )
      const importedAssignee = importedAssigneeField?.enum_value?.name || null

      // Use imported assignee if regular assignee is missing
      const finalAssignee = task.assignee?.name || importedAssignee || "Unassigned"

      return {
        key: task.gid || "-",
        issueType: "-",
        summary: task.name || "-",
        description: task.notes || "",
        priority: "-",
        status: task.completed ? "Done" : "Open",
        assignee: finalAssignee,
        team: task.memberships?.[0]?.section?.name || "-",
        startDate,
        due,
        duration,
      }
    })

    res.json({ issues: tasks })
  } catch (err) {
    console.error("[Asana API]", err)
    res.status(500).json({ error: "Failed to fetch Asana tasks", details: err instanceof Error ? err.message : "Unknown error" })
  }
})

// Fetch list of Asana projects (requires ASANA_TOKEN). Uses ASANA_WORKSPACE env if provided,
// otherwise returns the DEFAULT_ASANA_PROJECT_ID as a single-item list when available.
app.get('/api/asana/projects', async (_req: Request, res: Response) => {
  if (!isAsanaConfigReady) {
    return res.status(500).json({ error: 'Asana configuration missing' })
  }

  try {
    const workspace = process.env.ASANA_WORKSPACE_ID
    if (workspace) {
      const url = `${ASANA_BASE_URL}/projects?workspace=${workspace}&archived=false&opt_fields=gid,name,notes`;
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${ASANA_TOKEN}`,
          Accept: 'application/json',
        },
      })

      if (!response.ok) {
        const txt = await response.text()
        return res.status(response.status).json({ error: 'Failed to fetch Asana projects', details: txt })
      }

      const data = await response.json() as any
      const values = data.data || []
      const projects = values.map((p: any) => ({
        id: p.gid,
        key: p.gid,
        title: p.name,
        description: p.notes || '',
        avatar: '',
      }))

      return res.json({ projects })
    }

    // If no workspace provided, try returning the default project if set
    if (DEFAULT_ASANA_PROJECT_ID) {
      const url = `${ASANA_BASE_URL}/projects/${DEFAULT_ASANA_PROJECT_ID}?opt_fields=gid,name,notes`;
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${ASANA_TOKEN}`,
          Accept: 'application/json',
        },
      })

      if (!response.ok) {
        const txt = await response.text()
        return res.status(response.status).json({ error: 'Failed to fetch Asana project', details: txt })
      }

      const data = await response.json() as any
      const p = data.data
      const project = p ? [{ id: p.gid, key: p.gid, title: p.name, description: p.notes || '', avatar: '' }] : []
      return res.json({ projects: project })
    }

    // No workspace and no default project configured
    return res.json({ projects: [] })
  } catch (err) {
    console.error('[Asana Projects]', err)
    return res.status(500).json({ error: 'Failed to fetch Asana projects', details: err instanceof Error ? err.message : 'Unknown' })
  }
})

// ============ JIRA API Routes ============
app.get("/api/issues", async (req: Request, res: Response) => {
  const projectKey = (req.query.projectKey as string) || PROJECT_KEY

  console.log('[/api/issues] Request for project:', projectKey, 'Auth ready:', !!auth)

  if (!projectKey) {
    return res.status(400).json({ error: "Project key is required" })
  }

  if (!isJiraConfigReady) {
    console.error('[/api/issues] Jira not configured')
    return res.status(500).json({ error: "Jira configuration missing" })
  }

  try {
    const jql = `project = "${projectKey}"`
    // Use correct Jira Cloud API v3 endpoint format
    const url = `https://${DOMAIN}/rest/api/3/search/jql?jql=${encodeURIComponent(jql)}&maxResults=500&fields=key,summary,created,duedate,description,priority,status,assignee,issuetype`
    
    console.log('[Jira Request] URL:', url)
    console.log('[Jira Request] Auth header set:', !!auth)
    
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
    })

    console.log('[Jira Response] Status:', response.status)

    if (!response.ok) {
      const text = await response.text()
      console.error('[Jira Error] Status:', response.status, 'Response:', text.substring(0, 200))
      return res.status(response.status).json({ error: 'Failed to fetch Jira issues', status: response.status, details: text })
    }

    const data = await response.json() as any
    const issues = (data.issues || []).map((issue: any) => {
      const fields = issue.fields || {}
      const created = fields.created || null
      const due = fields.duedate || null
      const duration = created && due ? Math.ceil((new Date(due).getTime() - new Date(created).getTime()) / MS_PER_DAY) : ""

      return {
        key: issue.key || "-",
        issueType: fields.issuetype?.name || "-",
        summary: fields.summary || "-",
        description: extractDescription(fields.description),
        priority: fields.priority?.name || "-",
        status: fields.status?.name || "-",
        assignee: fields.assignee?.displayName || "Unassigned",
        team: TEAM_FIELD && fields[TEAM_FIELD] ? String(fields[TEAM_FIELD]) : "Team 1",
        created,
        due,
        duration,
      }
    })

    res.json({ issues })
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch Jira issues", details: err instanceof Error ? err.message : "Unknown error" })
  }
})

app.get('/api/projects', async (_req: Request, res: Response) => {
  if (!isJiraConfigReady || !DOMAIN) {
    return res.status(500).json({ error: 'Jira configuration missing' })
  }

  try {
    const response = await fetch(`https://${DOMAIN}/rest/api/2/project?maxResults=200`, {
      headers: {
        Authorization: `Basic ${auth}`,
        Accept: 'application/json',
      },
    })

    if (!response.ok) {
      const txt = await response.text()
      return res.status(response.status).json({ error: 'Failed to fetch projects', details: txt })
    }

    const data = await response.json() as any
    // Jira API v2 /project returns a direct array
    const projectArray = Array.isArray(data) ? data : (data.values || data.projects || [])
    const projects = projectArray.map((p: any) => ({
      id: p.key || String(p.id),
      key: p.key || String(p.id),
      title: p.name || p.key || String(p.id),
      category: p.projectTypeKey || 'Project',
      description: p.description ? (typeof p.description === 'string' ? p.description : '') : '',
      avatar: p.avatarUrls?.['48x48'] || '',
    }))
    
    console.log('[/api/projects] Returning', projects.length, 'projects')
    res.json({ projects })
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch Jira projects', details: err instanceof Error ? err.message : 'Unknown' })
  }
})

// Microsoft 365 API routes
app.get('/api/microsoft/me', async (req: Request, res: Response) => {
  try {
    const me = await getMe(req);
    res.json(me);
  } catch (err: any) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.get('/api/microsoft/calendar', async (req: Request, res: Response) => {
  try {
    const { start, end } = req.query as { start?: string; end?: string };
    if (!start || !end) {
      return res.status(400).json({ error: 'start and end query params required (ISO strings)' });
    }
    const currentUser = (req.session as any)?.tokens?.account;
    if (!currentUser?.oid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }
    const events = await getUserCalendarEvents(req, currentUser.oid, start, end);
    res.json(events);
  } catch (err: any) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.get('/api/microsoft/meetings', async (req: Request, res: Response) => {
  try {
    const meetings = await getOnlineMeetings(req);
    res.json({ meetings });
  } catch (err: any) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.get('/api/microsoft/email', async (req: Request, res: Response) => {
  try {
    const period = req.query.period as string || 'D30';
    const report = await getEmailActivityReport(req, period);
    res.json({ report });
  } catch (err: any) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.get('/api/microsoft/chat', async (req: Request, res: Response) => {
  try {
    const chats = await getChats(req);
    res.json({ chats });
  } catch (err: any) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ROI route
app.get('/api/microsoft/roi', async (req: Request, res: Response) => {
  try {
    const { beforeStart, beforeEnd, afterStart, afterEnd, costPerHour } = req.query as {
      beforeStart?: string;
      beforeEnd?: string;
      afterStart?: string;
      afterEnd?: string;
      costPerHour?: string;
    };
    if (!beforeStart || !beforeEnd || !afterStart || !afterEnd) {
      return res.status(400).json({ error: 'Please provide beforeStart,beforeEnd,afterStart,afterEnd query params (ISO).' });
    }

    const currentUser = (req.session as any)?.tokens?.account;
    if (!currentUser?.oid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const userId = currentUser.oid;
    const users = [{ id: userId, displayName: currentUser.name || 'Current User' }];

    const results = [];
    for (const u of users) {
      const userId = u.id;

      const beforeEvents = await getUserCalendarEvents(req, userId, beforeStart, beforeEnd).catch(() => ({ value: [] }));
      const afterEvents = await getUserCalendarEvents(req, userId, afterStart, afterEnd).catch(() => ({ value: [] }));

      function sumMeetingMinutes(evList: any): number {
        const list = evList.value || [];
        let total = 0;
        for (const ev of list) {
          try {
            const start = new Date(ev.start.dateTime);
            const end = new Date(ev.end.dateTime);
            const duration = (end.getTime() - start.getTime()) / (1000 * 60);
            total += duration;
          } catch (e) {
            console.warn('Error parsing event:', ev);
          }
        }
        return total;
      }

      const beforeMinutes = sumMeetingMinutes(beforeEvents);
      const afterMinutes = sumMeetingMinutes(afterEvents);
      const timeSavedMinutes = Math.max(0, beforeMinutes - afterMinutes);
      const timeSavedHours = timeSavedMinutes / 60;
      const costPerHourNum = costPerHour ? parseFloat(costPerHour) : 50;
      const valueGenerated = timeSavedHours * costPerHourNum;

      results.push({
        user: u.displayName,
        beforeMeetingMinutes: beforeMinutes,
        afterMeetingMinutes: afterMinutes,
        timeSavedMinutes,
        timeSavedHours,
        costPerHour: costPerHourNum,
        valueGenerated
      });
    }

    res.json({ results });
  } catch (err: any) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok" })
})

app.listen(PORT, () => {
  console.log(`API server listening on http://localhost:${PORT}`)
  console.log(`  - Jira API: ${isJiraConfigReady ? 'configured' : 'NOT configured'}`)
  console.log(`  - Asana API: ${isAsanaConfigReady ? 'configured' : 'NOT configured'}`)
  console.log(`  - Microsoft 365 API: ${isMicrosoftConfigReady ? 'configured' : 'NOT configured'}`)
})

// Export for Vercel serverless
export default app
