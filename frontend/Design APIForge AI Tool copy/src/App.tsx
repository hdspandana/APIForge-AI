import { useState, useEffect, useRef, useCallback } from "react";

// ─── Constants ─────────────────────────────────────────────────────────────
type AnalysisResult = {
  endpoints: {
    method: string;
    path: string;
    function: string;
    parameters: {
      name: string;
      type: string;
      location: string;
    }[];
  }[];
  documentation?: {
  summary: string;
  purpose: string;
  parameters: {
    name: string;
    type: string;
    location: string;
  }[];
  framework: string;
  data_source: string;
  authentication: string;
  use_cases: string[];
  context: string;
};
context?: {
    module: string;
    purpose: string;
    framework: string;
    data_source: string;
    authentication: string;
    related_endpoints: string[];
  };

  security?: {
    type: string;
    severity: string;
    message: string;
  }[];
  

};

const SAMPLE_RAW = `from flask import Flask, request, jsonify
from functools import wraps
import jwt, os, psycopg2

app = Flask(__name__)

# WARNING: Do not expose — production secret key
API_KEY = "sk-prod-abc123xyz789secret"
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-dev-secret")
DB_URL = os.getenv("DATABASE_URL")

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").split(" ")[-1]
        if not token:
            return jsonify({"error": "Unauthorized"}), 401
        try:
            jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 403
        return f(*args, **kwargs)
    return decorated

@app.route("/users", methods=["GET"])
@require_auth
def get_users():
    """Retrieve paginated list of users."""
    page  = request.args.get("page",  1,    type=int)
    limit = request.args.get("limit", 20,   type=int)
    role  = request.args.get("role",  None)
    users = User.query.filter_by(role=role).paginate(page, limit)
    return jsonify(users.to_dict()), 200

@app.route("/users", methods=["POST"])
@require_auth
def create_user():
    """Create a new user account."""
    data  = request.get_json()
    user  = User(name=data["name"], email=data["email"],
                 role=data.get("role", "user"))
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict()), 201

@app.route("/users/<int:id>", methods=["GET"])
@require_auth
def get_user(id):
    """Retrieve a specific user by ID."""
    user = User.query.get_or_404(id)
    return jsonify(user.to_dict()), 200

@app.route("/users/<int:id>", methods=["DELETE"])
@require_auth
def delete_user(id):
    """Permanently delete a user record."""
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "Deleted"}), 200

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=8080)
`;

type TokenType = "kw" | "fn" | "str" | "num" | "comment" | "dec" | "param" | "op" | "redacted" | "secret" | "plain";
interface Token { type: TokenType; text: string }

function tokenizePython(src: string): Token[][] {
  const lines = src.split("\n");
  return lines.map((line): Token[] => {
    // Comment line
    if (/^\s*#/.test(line)) {
      return [{ type: "comment", text: line }];
    }
    // Detect secret line and partially redact
    if (/API_KEY\s*=/.test(line)) {
      return [
        { type: "dec", text: "API_KEY" },
        { type: "op", text: " = " },
        { type: "secret", text: '"sk-prod-abc123xyz789secret"' },
        { type: "plain", text: "  " },
        { type: "redacted", text: "[REDACTED]" },
      ];
    }
    const tokens: Token[] = [];
    let rest = line;
    while (rest.length > 0) {
      // string literals
      const strM = rest.match(/^(f?["'].*?["'])/);
      if (strM) { tokens.push({ type: "str", text: strM[1] }); rest = rest.slice(strM[1].length); continue; }
      // keywords
      const kwM = rest.match(/^(from|import|def|return|if|not|try|except|class|and|or|None|True|False|as|with|for|in|async|await|raise|pass)\b/);
      if (kwM) { tokens.push({ type: "kw", text: kwM[1] }); rest = rest.slice(kwM[1].length); continue; }
      // decorators
      const decM = rest.match(/^(@\w+)/);
      if (decM) { tokens.push({ type: "dec", text: decM[1] }); rest = rest.slice(decM[1].length); continue; }
      // function calls / definitions
      const fnM = rest.match(/^(\w+)(?=\s*\()/);
      if (fnM) { tokens.push({ type: "fn", text: fnM[1] }); rest = rest.slice(fnM[1].length); continue; }
      // numbers
      const numM = rest.match(/^(\d+)/);
      if (numM) { tokens.push({ type: "num", text: numM[1] }); rest = rest.slice(numM[1].length); continue; }
      // operators
      const opM = rest.match(/^([\=\+\-\*\/\[\]\{\}\:\,\.]+)/);
      if (opM) { tokens.push({ type: "op", text: opM[1] }); rest = rest.slice(opM[1].length); continue; }
      // plain text (identifiers, spaces)
      const plainM = rest.match(/^([^\s"'@\w\d=+\-*/[\]{}:,.]+|\w+|[ \t]+)/);
      if (plainM) { tokens.push({ type: "plain", text: plainM[1] }); rest = rest.slice(plainM[1].length); continue; }
      tokens.push({ type: "plain", text: rest[0] }); rest = rest.slice(1);
    }
    return tokens;
  });
}



const FLOW_STEPS = ["CODE", "SECURITY", "PARSE", "CONTEXT", "AI DOCS", "QUALITY"] as const;

const QUALITY_CHECKS = [
  { label: "Endpoint coverage",  score: 100, pass: true },
  { label: "HTTP method docs",   score: 95,  pass: true },
  { label: "Parameter types",    score: 90,  pass: true },
  { label: "Context inference",  score: 82,  pass: true },
  { label: "Data flow mapping",  score: 85,  pass: true },
  { label: "Error scenarios",    score: 75,  pass: true },
];

const NAV_TABS = ["Dashboard", "Documentation", "API Changes", "Settings"] as const;
type NavTab = (typeof NAV_TABS)[number];

// ─── Primitives ─────────────────────────────────────────────────────────────

function Icon({ d, size = 14, stroke = "currentColor", strokeWidth = 1.5 }: { d: string; size?: number; stroke?: string; strokeWidth?: number }) {
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d={d} stroke={stroke} strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function MethodBadge({ method }: { method: string }) {
  return <span className={`method method-${method.toLowerCase()}`}>{method}</span>;
}

function StatusBadge({ status }: { status: string }) {
  const cls = status === "active" ? "badge-green" : status === "stable" ? "badge-cyan" : "badge-yellow";
  return <span className={`badge ${cls}`}>{status}</span>;
}

function SectionHeader({ icon, title, right }: { icon: React.ReactNode; title: string; right?: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "13px 16px", borderBottom: "1px solid var(--border)" }}>
      <span style={{ color: "var(--accent)", display: "flex", alignItems: "center", opacity: 0.8 }}>{icon}</span>
      <span style={{ fontFamily: "'Outfit', sans-serif", fontSize: 13.5, fontWeight: 600, color: "var(--text)", letterSpacing: "-0.01em" }}>{title}</span>
      {right && <div style={{ marginLeft: "auto" }}>{right}</div>}
    </div>
  );
}

// ─── Navbar ─────────────────────────────────────────────────────────────────

function NavBar({ tab, setTab }: { tab: NavTab; setTab: (t: NavTab) => void }) {
  return (
    <header style={{ position: "sticky", top: 0, zIndex: 60, background: "rgba(7,7,14,0.92)", backdropFilter: "blur(16px) saturate(1.4)", borderBottom: "1px solid var(--border)" }}>
      <div style={{ maxWidth: 1440, margin: "0 auto", padding: "0 28px", display: "flex", alignItems: "center", height: 54, gap: 0 }}>

        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginRight: 36, flexShrink: 0 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 9,
            background: "linear-gradient(135deg, #7c6dfa 0%, #a855f7 100%)",
            display: "flex", alignItems: "center", justifyContent: "center",
            boxShadow: "0 0 18px rgba(124,109,250,0.45), 0 2px 0 rgba(255,255,255,0.08) inset",
          }}>
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <rect x="2" y="3" width="12" height="1.5" rx="0.75" fill="white" opacity="0.9"/>
              <rect x="2" y="7" width="8" height="1.5" rx="0.75" fill="white" opacity="0.7"/>
              <rect x="2" y="11" width="10" height="1.5" rx="0.75" fill="white" opacity="0.5"/>
              <circle cx="13" cy="11.75" r="2.5" fill="#06b6d4" opacity="0.9"/>
            </svg>
          </div>
          <span style={{ fontFamily: "'Outfit', sans-serif", fontWeight: 700, fontSize: 15.5, color: "var(--text)", letterSpacing: "-0.03em" }}>
            APIForge <span style={{ color: "#a89dff" }}>AI</span>
          </span>
        </div>

        {/* Nav */}
        <nav style={{ display: "flex", gap: 2, flex: 1 }}>
          {NAV_TABS.map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              padding: "5px 13px", border: "none", cursor: "pointer", borderRadius: "var(--radius-sm)", fontSize: 13,
              fontWeight: tab === t ? 600 : 400,
              background: tab === t ? "rgba(124,109,250,0.13)" : "transparent",
              color: tab === t ? "#a89dff" : "var(--text-2)",
              transition: "background 140ms, color 140ms",
              fontFamily: "'Inter', sans-serif",
            }}>{t}</button>
          ))}
        </nav>

        {/* Right */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <a href="#" style={{ display: "flex", alignItems: "center", gap: 6, padding: "5px 12px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border)", color: "var(--text-2)", textDecoration: "none", fontSize: 12.5, transition: "border-color 140ms, color 140ms" }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = "var(--border-2)"; (e.currentTarget as HTMLElement).style.color = "var(--text)"; }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = "var(--border)"; (e.currentTarget as HTMLElement).style.color = "var(--text-2)"; }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
            GitHub
          </a>
          <div style={{ width: 30, height: 30, borderRadius: "50%", background: "linear-gradient(135deg, #7c6dfa, #a855f7)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700, color: "white", flexShrink: 0 }}>D</div>
        </div>
      </div>
    </header>
  );
}

// ─── Hero ────────────────────────────────────────────────────────────────────

function Hero({ onAnalyze, analyzing }: { onAnalyze: () => void; analyzing: boolean }) {
  return (
    <section style={{ padding: "56px 28px 40px", maxWidth: 1440, margin: "0 auto", position: "relative" }}>
      {/* Ambient glow */}
      <div style={{ position: "absolute", top: -40, left: "50%", transform: "translateX(-50%)", width: 700, height: 320, background: "radial-gradient(ellipse, rgba(124,109,250,0.09) 0%, transparent 68%)", pointerEvents: "none" }} />

      {/* Pill badge */}
      <div style={{ display: "flex", justifyContent: "center", marginBottom: 22 }}>
        <div style={{ display: "inline-flex", alignItems: "center", gap: 7, padding: "4px 14px 4px 8px", borderRadius: 20, border: "1px solid rgba(124,109,250,0.3)", background: "rgba(124,109,250,0.07)", fontSize: 11.5, fontFamily: "'JetBrains Mono', monospace", fontWeight: 500, color: "#a89dff" }}>
          <span className="animate-pulse-dot" style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--green)", display: "inline-block" }} />
AI ANALYSIS ENGINE · CONTEXT-AWARE        </div>
      </div>

      {/* Headline */}
      <h1 className="font-display grad-text" style={{ textAlign: "center", fontSize: "clamp(34px, 4.2vw, 58px)", fontWeight: 800, lineHeight: 1.08, letterSpacing: "-0.04em", marginBottom: 18, maxWidth: 780, marginLeft: "auto", marginRight: "auto" }}>
        Turn API Code Into<br />Intelligent Documentation
      </h1>
      <p style={{ textAlign: "center", fontSize: 15.5, color: "var(--text-2)", maxWidth: 520, margin: "0 auto 36px", lineHeight: 1.7 }}>
        Analyze API code, detect secrets, understand context, and generate accurate documentation with AI.
      </p>

      {/* Flow pipeline */}
      <div className="flow-bar" style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 0, flexWrap: "wrap" }}>
        {FLOW_STEPS.map((step, i) => (
          <div key={step} style={{ display: "flex", alignItems: "center" }}>
            <div style={{
              display: "flex", alignItems: "center", gap: 6,
              padding: "5px 13px", borderRadius: "var(--radius-sm)",
              border: `1px solid ${i < 3 ? "rgba(124,109,250,0.28)" : "var(--border)"}`,
              background: i < 3 ? "rgba(124,109,250,0.08)" : "var(--surface)",
              fontFamily: "'JetBrains Mono', monospace", fontSize: 10.5, fontWeight: 600,
              color: i < 3 ? "#a89dff" : "var(--text-3)",
              letterSpacing: "0.05em", whiteSpace: "nowrap",
            }}>
              {i === 0 && <svg width="9" height="9" viewBox="0 0 9 9" fill="none"><rect x="0.75" y="0.75" width="7.5" height="7.5" rx="1.5" stroke="currentColor" strokeWidth="1.2"/></svg>}
              {step}
            </div>
            {i < FLOW_STEPS.length - 1 && (
              <svg width="22" height="10" viewBox="0 0 22 10" fill="none" style={{ flexShrink: 0 }}>
                <path d="M0 5h17M13 1.5l4 3.5-4 3.5" stroke={i < 2 ? "var(--accent)" : "var(--border-2)"} strokeWidth="1.1" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}

// ─── Code Editor ─────────────────────────────────────────────────────────────

function SyntaxLine({ tokens }: { tokens: Token[] }) {
  return (
    <div style={{ lineHeight: "20px", minHeight: 20 }}>
      {tokens.map((tok, i) => (
        <span key={i} className={tok.type !== "plain" ? `tok-${tok.type}` : undefined} style={{ color: tok.type === "plain" ? "var(--text-2)" : undefined }}>
          {tok.text}
        </span>
      ))}
    </div>
  );
}

function CodeEditor({ code, setCode, onAnalyze, analyzing }: {
  code: string; setCode: (c: string) => void;
  onAnalyze: () => void; analyzing: boolean;
}) {
  const lines = code.split("\n");
  const tokenized = tokenizePython(code);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const highlightRef = useRef<HTMLDivElement>(null);

  const syncScroll = useCallback(() => {
    if (textareaRef.current && highlightRef.current) {
      highlightRef.current.scrollTop = textareaRef.current.scrollTop;
      highlightRef.current.scrollLeft = textareaRef.current.scrollLeft;
    }
  }, []);

  return (
    <div className="panel" style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* Title bar */}
      <div style={{ padding: "11px 16px", borderBottom: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ display: "flex", gap: 5, flexShrink: 0 }}>
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#ff5f57" }} />
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#febc2e" }} />
          <div style={{ width: 10, height: 10, borderRadius: "50%", background: "#28c840" }} />
        </div>
        <span style={{ fontFamily: "'Outfit', sans-serif", fontSize: 13, fontWeight: 600, color: "var(--text)", flex: 1 }}>API Source Code</span>
        <span className="badge badge-accent">Python</span>
        <div style={{ display: "flex", gap: 5 }}>
          <button className="btn-ghost" onClick={() => navigator.clipboard?.writeText(code)}>Copy</button>
          <button className="btn-ghost" onClick={() => setCode(SAMPLE_RAW)}>Sample</button>
          <button className="btn-ghost" onClick={() => setCode("")}>Clear</button>
        </div>
      </div>

      {/* Editor body */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden", minHeight: 380 }}>
        {/* Line numbers */}
        <div style={{ background: "rgba(0,0,0,0.25)", borderRight: "1px solid var(--border)", padding: "14px 0", userSelect: "none", flexShrink: 0, overflowY: "hidden", minWidth: 44 }}>
          {lines.map((_, i) => (
            <div key={i} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11.5, lineHeight: "20px", color: "var(--text-3)", textAlign: "right", paddingRight: 12, paddingLeft: 8 }}>{i + 1}</div>
          ))}
        </div>

        {/* Highlight + textarea overlay */}
        <div className="code-host" style={{ flex: 1, overflow: "hidden" }}>
          <div ref={highlightRef} className="code-highlight" style={{ overflow: "hidden" }}>
            {tokenized.map((tokLine, i) => <SyntaxLine key={i} tokens={tokLine} />)}
          </div>
          <textarea
            ref={textareaRef}
            value={code}
            onChange={e => setCode(e.target.value)}
            placeholder="Paste your API code here..."
            onScroll={syncScroll}
            spellCheck={false}
            className="code-textarea"
          />
        </div>
      </div>

      {/* Footer */}
      <div style={{ padding: "10px 16px", borderTop: "1px solid var(--border)", display: "flex", alignItems: "center", gap: 12 }}>
        <span className="font-mono" style={{ fontSize: 10.5, color: "var(--text-3)" }}>
          {lines.length} ln · {code.length} ch
        </span>
        <span style={{ flex: 1 }} />
        <button className="btn-primary" onClick={onAnalyze} disabled={analyzing || !code.trim()}>
          {analyzing ? (
            <>
              <div className="animate-spin" style={{ width: 13, height: 13, border: "2px solid rgba(255,255,255,0.3)", borderTop: "2px solid white", borderRadius: "50%" }} />
              Analyzing…
            </>
          ) : (
            <>
              <svg width="13" height="13" viewBox="0 0 13 13" fill="none"><circle cx="6.5" cy="6.5" r="5" stroke="white" strokeWidth="1.3"/><path d="M4.5 6.5l1.5 1.5 2.5-3" stroke="white" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg>
              Analyze API
            </>
          )}
        </button>
      </div>
    </div>
  );
}

// ─── Stat Cards ──────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, accent = "var(--accent)", icon }: {
  label: string; value: string | number; sub?: string; accent?: string; icon?: React.ReactNode;
}) {
  return (
    <div className="panel" style={{ padding: "15px 16px", transition: "border-color 160ms, box-shadow 160ms" }}
      onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = "var(--border-2)"; el.style.boxShadow = "0 4px 20px rgba(0,0,0,0.35)"; }}
      onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = "var(--border)"; el.style.boxShadow = "none"; }}>
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 8 }}>
        <span className="section-label" style={{ fontSize: 9.5 }}>{label}</span>
        {icon && <span style={{ color: accent, opacity: 0.65 }}>{icon}</span>}
      </div>
      <div style={{ fontFamily: "'Outfit', sans-serif", fontSize: 30, fontWeight: 700, color: accent, lineHeight: 1, letterSpacing: "-0.04em" }}>{value}</div>
      {sub && <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: "var(--text-3)", marginTop: 5 }}>{sub}</div>}
    </div>
  );
}

// ─── Security Scan ───────────────────────────────────────────────────────────

function SecurityScan({
  analysisResult,
}: {
  analysisResult: AnalysisResult | null;
}) {
  const securityIssues = analysisResult?.security ?? [];

  return (
    <div className="panel">
      <SectionHeader
        icon={
          <svg
            width="13"
            height="13"
            viewBox="0 0 13 13"
            fill="none"
          >
            <path
              d="M6.5 1L1.5 3v3.5C1.5 9.8 3.7 12.1 6.5 12.5 9.3 12.1 11.5 9.8 11.5 6.5V3L6.5 1z"
              stroke="currentColor"
              strokeWidth="1.3"
            />
          </svg>
        }
        title="Security Scan"
        right={
          <span
            className={
              securityIssues.length
                ? "badge badge-yellow"
                : "badge badge-green"
            }
          >
            <span
              style={{
                width: 5,
                height: 5,
                borderRadius: "50%",
                background: securityIssues.length
                  ? "var(--yellow)"
                  : "var(--green)",
                display: "inline-block",
              }}
            />
            {securityIssues.length
              ? "ISSUE DETECTED"
              : "PASSED"}
          </span>
        }
      />

      <div
        style={{
          padding: "13px 16px",
          display: "flex",
          flexDirection: "column",
          gap: 8,
        }}
      >
        {/* Security status */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            padding: "9px 12px",
            borderRadius: "var(--radius-sm)",
            background: securityIssues.length
              ? "var(--yellow-dim)"
              : "var(--green-dim)",
            border: securityIssues.length
              ? "1px solid rgba(245,158,11,0.2)"
              : "1px solid rgba(16,185,129,0.18)",
          }}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 14 14"
            fill="none"
          >
            <circle
              cx="7"
              cy="7"
              r="6"
              stroke={
                securityIssues.length
                  ? "#f59e0b"
                  : "#10b981"
              }
              strokeWidth="1.3"
            />
            <path
              d={
                securityIssues.length
                  ? "M7 4v3.5M7 9.5v.1"
                  : "M4.5 7l1.8 1.8L9.5 5"
              }
              stroke={
                securityIssues.length
                  ? "#f59e0b"
                  : "#10b981"
              }
              strokeWidth="1.4"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>

          <span
            style={{
              fontSize: 12.5,
              color: "var(--text)",
            }}
          >
            {securityIssues.length
              ? `${securityIssues.length} security issue${
                  securityIssues.length > 1 ? "s" : ""
                } detected`
              : "No security issues detected"}
          </span>
        </div>

        {/* Actual security findings */}
        {securityIssues.map((issue, index) => (
          <div
            key={index}
            style={{
              padding: "9px 12px",
              borderRadius: "var(--radius-sm)",
              background: "var(--yellow-dim)",
              border:
                "1px solid rgba(245,158,11,0.2)",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                marginBottom: 8,
              }}
            >
              <svg
                width="14"
                height="14"
                viewBox="0 0 14 14"
                fill="none"
              >
                <path
                  d="M7 2L1.5 11.5h11L7 2z"
                  stroke="#f59e0b"
                  strokeWidth="1.3"
                  strokeLinejoin="round"
                />
                <line
                  x1="7"
                  y1="6"
                  x2="7"
                  y2="9"
                  stroke="#f59e0b"
                  strokeWidth="1.4"
                  strokeLinecap="round"
                />
                <circle
                  cx="7"
                  cy="10.5"
                  r="0.6"
                  fill="#f59e0b"
                />
              </svg>

              <span
                style={{
                  fontSize: 12.5,
                  color: "var(--text)",
                  fontWeight: 500,
                }}
              >
                {issue.message}
              </span>
            </div>

            <div
              style={{
                fontSize: 11,
                color: "var(--text-3)",
              }}
            >
              Type: {issue.type} · Severity: {issue.severity}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Endpoints Table ──────────────────────────────────────────────────────────

function EndpointsTable({
  activeIdx,
  setActiveIdx,
  analysisResult,
}: {
  
  activeIdx: number;
  setActiveIdx: (i: number) => void;
  analysisResult: AnalysisResult | null;
}) {  
  const endpoints = analysisResult?.endpoints ?? [];
  return (
    <div className="panel" style={{ overflow: "hidden" }}>
      <SectionHeader
        icon={<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><rect x="1" y="1" width="11" height="11" rx="2" stroke="currentColor" strokeWidth="1.3"/><path d="M4 4.5h5M4 6.5h3M4 8.5h4" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/></svg>}
        title="Detected Endpoints"
right={
  <span className="badge badge-accent">
    {analysisResult?.endpoints?.length ?? 0} endpoints
  </span>
}      />
      <div style={{ overflowX: "auto" }}>
        <table className="data-table">
          <thead>
            <tr>
              {["Method", "Endpoint", "Function", "Parameters", "Status"].map(h => (
                <th key={h}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {endpoints.map((ep, i) => (
              <tr
  key={i}
  onClick={() => setActiveIdx(i)}
  style={{
    background:
      activeIdx === i
        ? "rgba(124,109,250,0.06)"
        : undefined,
  }}
>
  <td>
    <MethodBadge method={ep?.method ?? "GET"} />
  </td>

  <td
    className="font-mono"
    style={{
      fontSize: 12,
      color:
        activeIdx === i
          ? "#a89dff"
          : "var(--text)",
    }}
  >
    {ep.path}
  </td>

  <td
    className="font-mono"
    style={{
      fontSize: 11.5,
      color: "var(--accent)",
    }}
  >
    {ep.function}()
  </td>

  <td
    className="font-mono"
    style={{
      fontSize: 11,
      color: "var(--text-2)",
    }}
  >
    {ep.parameters.map((p) => p.name).join(", ") || "—"}
  </td>

  <td>
<StatusBadge status="ACTIVE" />  </td>
</tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Doc Viewer ───────────────────────────────────────────────────────────────

const EP_DOCS = [
  {
    purpose: "Returns a paginated, role-filtered list of all user accounts.",
    params: [{ name: "page", type: "integer", req: false, desc: "Page index, 1-based (default 1)" }, { name: "limit", type: "integer", req: false, desc: "Records per page, max 100 (default 20)" }, { name: "role", type: "string", req: false, desc: "Filter by role: user | admin | moderator" }],
    response: '{\n  "users": [\n    {"id": 42, "name": "Alice Chen",\n     "email": "alice@acme.com",\n     "role": "admin"}\n  ],\n  "total": 138, "page": 1\n}',
    errors: [{ code: "401", msg: "Missing Authorization header" }, { code: "403", msg: "JWT signature invalid or expired" }],
    useCases: ["Admin user-management dashboard", "Role-based access control listing", "Paginated user directory view"],
    sourceItems: ["JWT auth decorator applied", "Route: GET /users", "Handler: get_users()"],
    inferredItems: ["Targets user collection", "Reads from DB via ORM", "Supports cursor pagination"],
  },
  {
    purpose: "Creates a new user account, persists it to the database, and returns the created record.",
    params: [{ name: "name", type: "string", req: true, desc: "Full display name of the user" }, { name: "email", type: "string", req: true, desc: "Unique email address for login" }, { name: "role", type: "string", req: false, desc: "Account role (default: user)" }],
    response: '{\n  "id": 143,\n  "name": "Bob Okafor",\n  "email": "bob@acme.com",\n  "role": "user",\n  "created_at": "2026-09-12T10:24:00Z"\n}',
    errors: [{ code: "400", msg: "name or email missing from body" }, { code: "409", msg: "Email address already registered" }, { code: "422", msg: "Invalid email format" }],
    useCases: ["User registration flow", "Admin bulk import", "Invitation acceptance callback"],
    sourceItems: ["JWT auth required", "Route: POST /users", "Reads JSON body: name, email, role"],
    inferredItems: ["Persists via db.session.commit()", "Returns 201 on creation", "Email uniqueness enforced"],
  },
  {
    purpose: "Retrieves a single user record by unique integer ID. Raises 404 if not found.",
    params: [{ name: "id", type: "integer", req: true, desc: "Unique user identifier (path parameter)" }],
    response: '{\n  "id": 42,\n  "name": "Alice Chen",\n  "email": "alice@acme.com",\n  "role": "admin",\n  "created_at": "2025-03-01T09:00:00Z"\n}',
    errors: [{ code: "401", msg: "Missing Authorization header" }, { code: "403", msg: "JWT signature invalid or expired" }, { code: "404", msg: "User with given id not found" }],
    useCases: ["Profile page rendering", "Account settings lookup", "Permission verification middleware"],
    sourceItems: ["JWT auth required", "Route: GET /users/<int:id>", "Uses get_or_404() — auto 404"],
    inferredItems: ["Single-row DB read", "No write side-effects", "Safe to cache aggressively"],
  },
  {
    purpose: "Permanently removes the user record. Operation is irreversible — no soft-delete detected.",
    params: [{ name: "id", type: "integer", req: true, desc: "Unique user identifier to delete" }],
    response: '{\n  "message": "Deleted"\n}',
    errors: [{ code: "401", msg: "Missing Authorization header" }, { code: "403", msg: "JWT signature invalid or expired" }, { code: "404", msg: "User with given id not found" }],
    useCases: ["Account deletion self-service", "Admin user removal", "GDPR right-to-erasure flow"],
    sourceItems: ["JWT auth required", "Route: DELETE /users/<int:id>", "db.session.delete() — permanent"],
    inferredItems: ["Hard delete — no soft-delete flag detected", "Returns 200 not 204", "May cascade FK constraints"],
  },
];

function DocViewer({
  activeIdx,
  setActiveIdx,
  analysisResult,
}: {
  activeIdx: number;
  setActiveIdx: (i: number) => void;
  analysisResult: AnalysisResult | null;
}) {
  const endpoints = analysisResult?.endpoints ?? [];
  const ep = endpoints[activeIdx] ?? endpoints[0];

  const documentation =
    analysisResult?.documentation?.[activeIdx] ??
    analysisResult?.documentation?.[0];

  if (!ep) {
    return (
      <div className="panel" style={{ padding: 24 }}>
        <SectionHeader
          icon={<span>📄</span>}
          title="Generated Documentation"
        />
        <p style={{ color: "var(--text-2)", padding: 20 }}>
          Analyze an API to generate documentation.
        </p>
      </div>
    );
  }

  const useCases = documentation?.use_cases ?? [];

  const errorScenarios = [
  ...(ep.parameters.length > 0
    ? [
        {
          code: "400",
          msg: "Invalid or missing parameter.",
        },
      ]
    : []),

  ...(ep.path.includes("<") || ep.path.includes("{")
    ? [
        {
          code: "404",
          msg: "The requested resource was not found.",
        },
      ]
    : []),

  {
    code: "500",
    msg: "An unexpected server error occurred.",
  },
];

  const dataFlow = [
  "Client",

  ...(analysisResult?.context?.authentication &&
  analysisResult.context.authentication !== "Not detected"
    ? [analysisResult.context.authentication]
    : []),

  "→",

  `${ep.method} ${ep.path}`,

  "→",

  ep.function.replace(/_/g, " "),

  ...(analysisResult?.context?.data_source &&
  analysisResult.context.data_source !== "Unknown"
    ? ["→", analysisResult.context.data_source]
    : []),

  "→",
  "Response",
];

  return (
    <div className="panel" style={{ overflow: "hidden" }}>
      <SectionHeader
        icon={
          <svg
            width="13"
            height="13"
            viewBox="0 0 13 13"
            fill="none"
          >
            <rect
              x="1"
              y="1"
              width="11"
              height="11"
              rx="2"
              stroke="currentColor"
              strokeWidth="1.3"
            />
            <path
              d="M3.5 4h6M3.5 6.5h4"
              stroke="currentColor"
              strokeWidth="1.2"
              strokeLinecap="round"
            />
          </svg>
        }
        title="Generated Documentation"
        right={
          <span
            className="badge badge-accent"
            style={{
              fontSize: 9.5,
              letterSpacing: "0.05em",
            }}
          >
            Context-aware documentation
          </span>
        }
      />

      {/* Endpoint tabs */}
      <div
        style={{
          display: "flex",
          borderBottom: "1px solid var(--border)",
          overflowX: "auto",
        }}
      >
        {endpoints.map((ep2, i) => (
          <button
            key={i}
            onClick={() => setActiveIdx(i)}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "9px 14px",
              border: "none",
              borderBottom: `2px solid ${
                activeIdx === i
                  ? "var(--accent)"
                  : "transparent"
              }`,
              background:
                activeIdx === i
                  ? "rgba(124,109,250,0.07)"
                  : "transparent",
              color:
                activeIdx === i
                  ? "#a89dff"
                  : "var(--text-3)",
              cursor: "pointer",
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 11.5,
              whiteSpace: "nowrap",
              transition:
                "color 130ms, background 130ms",
            }}
          >
            <MethodBadge method={ep2.method} />
            {ep2.path}
          </button>
        ))}
      </div>

      {/* Content */}
      <div
        style={{
          padding: "20px",
          display: "flex",
          flexDirection: "column",
          gap: 18,
          maxHeight: 580,
          overflowY: "auto",
        }}
      >
        {/* Endpoint heading */}
        <div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 8,
              marginBottom: 8,
            }}
          >
            <MethodBadge method={ep.method} />

            <code
              className="font-mono"
              style={{
                fontSize: 15,
                fontWeight: 600,
                color: "var(--text)",
                letterSpacing: "-0.01em",
              }}
            >
              {ep.path}
            </code>
          </div>

          <p
            style={{
              fontSize: 13,
              color: "var(--text-2)",
              lineHeight: 1.7,
              margin: 0,
            }}
          >
            {documentation?.purpose ??
              "API endpoint operation"}
          </p>

          {documentation?.summary && (
            <div
              className="font-mono"
              style={{
                fontSize: 11,
                color: "var(--text-3)",
                marginTop: 6,
              }}
            >
              {documentation.summary}
            </div>
          )}
        </div>

        {/* Source vs Inferred */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 10,
          }}
        >
          {/* Source-derived */}
          <div
            style={{
              padding: "12px 14px",
              borderRadius: "var(--radius-sm)",
              background: "rgba(59,130,246,0.06)",
              border:
                "1px solid rgba(59,130,246,0.16)",
            }}
          >
            <div
              className="section-label"
              style={{
                color: "#60a5fa",
                marginBottom: 9,
              }}
            >
              Source-Derived
            </div>

            <div
              style={{
                fontSize: 11.5,
                color: "var(--text)",
                display: "flex",
                gap: 7,
                alignItems: "flex-start",
                marginBottom: 5,
              }}
            >
              <span style={{ color: "#60a5fa" }}>·</span>
              HTTP method: {ep.method}
            </div>

            <div
              style={{
                fontSize: 11.5,
                color: "var(--text)",
                display: "flex",
                gap: 7,
                alignItems: "flex-start",
                marginBottom: 5,
              }}
            >
              <span style={{ color: "#60a5fa" }}>·</span>
              Route: {ep.path}
            </div>

            <div
              style={{
                fontSize: 11.5,
                color: "var(--text)",
                display: "flex",
                gap: 7,
                alignItems: "flex-start",
                marginBottom: 5,
              }}
            >
              <span style={{ color: "#60a5fa" }}>·</span>
              Handler: {ep.function}()
            </div>

            <div
              style={{
                fontSize: 11.5,
                color: "var(--text)",
                display: "flex",
                gap: 7,
                alignItems: "flex-start",
              }}
            >
              <span style={{ color: "#60a5fa" }}>·</span>
              Parameters: {ep.parameters.length}
            </div>
          </div>

          {/* Inferred */}
          <div
            style={{
              padding: "12px 14px",
              borderRadius: "var(--radius-sm)",
              background: "rgba(168,85,247,0.06)",
              border:
                "1px solid rgba(168,85,247,0.16)",
            }}
          >
            <div
              className="section-label"
              style={{
                color: "#c084fc",
                marginBottom: 9,
              }}
            >
              Inferred
            </div>

            <div
              style={{
                fontSize: 11.5,
                color: "var(--text)",
                display: "flex",
                gap: 7,
                alignItems: "flex-start",
                marginBottom: 5,
              }}
            >
              <span style={{ color: "#c084fc" }}>·</span>
              Operation:{" "}
              {ep.function.replace(/_/g, " ")}
            </div>

            <div
              style={{
                fontSize: 11.5,
                color: "var(--text)",
                display: "flex",
                gap: 7,
                alignItems: "flex-start",
              }}
            >
              <span style={{ color: "#c084fc" }}>·</span>
              Purpose: {documentation?.purpose ?? "Unknown"}
            </div>
          </div>
        </div>

        {/* Parameters */}
        <div>
          <div
            className="section-label"
            style={{ marginBottom: 10 }}
          >
            Parameters
          </div>

          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 6,
            }}
          >
            {ep.parameters.length === 0 ? (
              <p
                style={{
                  fontSize: 13,
                  color: "var(--text-2)",
                }}
              >
                No parameters
              </p>
            ) : (
              (documentation?.parameters ??
                ep.parameters
              ).map((p) => (
                <div
                  key={p.name}
                  style={{
                    display: "grid",
                    gridTemplateColumns:
                      "1fr 1fr 1fr",
                    gap: 12,
                    padding: "10px 0",
                    borderBottom:
                      "1px solid var(--border)",
                  }}
                >
                  <code>{p.name}</code>
                  <span>{p.type}</span>
                  <span>{p.location}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Response */}
        <div>
          <div
            className="section-label"
            style={{ marginBottom: 10 }}
          >
            Example Response
          </div>

          <div
            className="panel-deep"
            style={{ padding: "13px 14px" }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: 8,
              }}
            >
              <span
                className="font-mono"
                style={{
                  fontSize: 10,
                  color: "var(--text-3)",
                }}
              >
                application/json
              </span>

              <span className="badge badge-green">
                200 OK
              </span>
            </div>

            <pre
              className="font-mono"
              style={{
                fontSize: 11.5,
                color: "var(--text-2)",
                lineHeight: 1.7,
                whiteSpace: "pre-wrap",
                margin: 0,
                padding: 14,
                borderRadius: "var(--radius-sm)",
                background: "var(--bg)",
                border:
                  "1px solid var(--border)",
                overflowX: "auto",
              }}
            >
              {JSON.stringify(
  documentation?.example_response ?? {},
  null,
  2
)}
            </pre>
          </div>
        </div>

        {/* Data Flow */}
        <div>
          <div
            className="section-label"
            style={{ marginBottom: 10 }}
          >
            Data Flow
          </div>

          <div
            style={{
              display: "flex",
              alignItems: "center",
              flexWrap: "wrap",
              gap: 6,
            }}
          >
            {dataFlow.map((step, i) => (
              <span
                key={i}
                className={
                  step !== "→"
                    ? "font-mono"
                    : undefined
                }
                style={{
                  fontSize: 12,
                  color:
                    step === "→"
                      ? "var(--text-3)"
                      : "var(--text)",
                  padding:
                    step !== "→"
                      ? "4px 10px"
                      : "0",
                  background:
                    step !== "→"
                      ? "var(--accent-dim)"
                      : "transparent",
                  border:
                    step !== "→"
                      ? "1px solid rgba(124,109,250,0.18)"
                      : "none",
                  borderRadius:
                    step !== "→"
                      ? "var(--radius-sm)"
                      : 0,
                }}
              >
                {step}
              </span>
            ))}
          </div>
        </div>

        {/* Errors */}
        <div>
          <div
            className="section-label"
            style={{ marginBottom: 10 }}
          >
            Error Scenarios
          </div>

          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 5,
            }}
          >
            {errorScenarios.map((err) => (
              <div
                key={err.code}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  padding: "8px 12px",
                  borderRadius:
                    "var(--radius-sm)",
                  background:
                    "var(--red-dim)",
                  border:
                    "1px solid rgba(244,63,94,0.13)",
                }}
              >
                <code
                  className="font-mono"
                  style={{
                    fontSize: 12,
                    color: "#fb7185",
                    minWidth: 34,
                  }}
                >
                  {err.code}
                </code>

                <span
                  style={{
                    fontSize: 12,
                    color: "var(--text-2)",
                  }}
                >
                  {err.msg}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Typical Use Cases */}
        {useCases.length > 0 && (
          <div>
            <div
              className="section-label"
              style={{ marginBottom: 10 }}
            >
              Typical Use Cases
            </div>

            {useCases.map((uc, i) => (
              <div
                key={i}
                style={{
                  fontSize: 12.5,
                  color: "var(--text-2)",
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  marginBottom: 6,
                }}
              >
                <svg
                  width="12"
                  height="12"
                  viewBox="0 0 12 12"
                  fill="none"
                >
                  <path
                    d="M2.5 6l2.5 2.5 5-5"
                    stroke="var(--accent)"
                    strokeWidth="1.3"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>

                {uc}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── API Context ──────────────────────────────────────────────────────────────

function ApiContext({
  analysisResult,
  activeIdx,
}: {
  analysisResult: AnalysisResult | null;
  activeIdx: number;
}) {
  const context = analysisResult?.context;
  const documentation = analysisResult?.documentation?.[activeIdx];

  const rows = [
    {
      label: "Module",
      value: context?.module ?? "Unknown",
      mono: true
    },
    {
      label: "Purpose",
      value:
  context?.purpose ??
  documentation?.purpose ??
  "API endpoint operations"
    },
    {
      label: "Framework",
      value: context?.framework ?? "Unknown",
      mono: true
    },
    {
      label: "Data Source",
      value: context?.data_source ?? "Unknown"
    },
    {
      label: "Authentication",
      value: context?.authentication ?? "Not detected"
    },
    {
      label: "Related Endpoints",
      value: context?.related_endpoints?.length
        ? context.related_endpoints.join(", ")
        : "—",
      mono: true
    },
  ];

  return (
    <div className="panel">
      <SectionHeader
        icon={
          <svg
            width="13"
            height="13"
            viewBox="0 0 13 13"
            fill="none"
          >
            <circle
              cx="6.5"
              cy="6.5"
              r="5.5"
              stroke="currentColor"
              strokeWidth="1.3"
            />
            <path
              d="M6.5 4v3l1.5 1"
              stroke="currentColor"
              strokeWidth="1.2"
              strokeLinecap="round"
            />
          </svg>
        }
        title="API Context"
        right={<span className="badge badge-cyan">
  Detected + Inferred
</span>}
      />

      <div style={{ padding: "4px 0" }}>
        {rows.map((row, i) => (
          <div
            key={row.label}
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "10px 16px",
              borderBottom:
                i < rows.length - 1
                  ? "1px solid rgba(30,30,53,0.7)"
                  : "none",
              gap: 20,
            }}
          >
            <span
              style={{
                fontSize: 12,
                color: "var(--text-2)",
                flexShrink: 0,
              }}
            >
              {row.label}
            </span>

            <span
              className={row.mono ? "font-mono" : undefined}
              style={{
                fontSize: row.mono ? 11.5 : 12.5,
                color: "var(--text)",
                textAlign: "right",
              }}
            >
              {row.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Quality Score ────────────────────────────────────────────────────────────

function QualityScore({
  analysisResult,
}: {
  analysisResult: AnalysisResult | null;
}) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setMounted(true), 120);
    return () => clearTimeout(t);
  }, []);

  const quality = analysisResult?.quality;
  const score = quality?.score ?? 0;

  return (
    <div className="panel">
      <SectionHeader
        icon={
          <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
            <path
              d="M6.5 1l1.5 3.2 3.5.5-2.5 2.4.6 3.4L6.5 9l-3.1 1.5.6-3.4L1.5 4.7l3.5-.5L6.5 1z"
              stroke="currentColor"
              strokeWidth="1.2"
              strokeLinejoin="round"
            />
          </svg>
        }
        title="Documentation Quality"
        right={
          <div style={{ display: "flex", alignItems: "baseline", gap: 2 }}>
            <span
              style={{
                fontFamily: "'Outfit', sans-serif",
                fontSize: 22,
                fontWeight: 700,
                color: "var(--accent)",
                lineHeight: 1,
                letterSpacing: "-0.04em",
              }}
            >
              {score}
            </span>
            <span
              style={{
                fontSize: 11,
                color: "var(--text-3)",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              /100
            </span>
          </div>
        }
      />

      <div
        style={{
          padding: "14px 16px",
          display: "flex",
          flexDirection: "column",
          gap: 10,
        }}
      >
        <div className="progress-track">
          <div
            className="progress-fill"
            style={{
              width: mounted ? `${score}%` : "0%",
            }}
          />
        </div>

        <div
          style={{
            fontSize: 12,
            color: "var(--text-2)",
          }}
        >
          Score based on endpoint detection, parameter parsing,
          framework detection, data source detection, and security analysis.
        </div>
      </div>
    </div>
  );
}
// ─── Analysis Panel ───────────────────────────────────────────────────────────

function AnalysisPanel({
  ready,
  docIdx,
  setDocIdx,
  analysisResult,
}: {
  ready: boolean;
  docIdx: number;
  setDocIdx: (i: number) => void;
  analysisResult: AnalysisResult | null;
}) {  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {/* Stats grid */}
      <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
        <StatCard label="Endpoints" value={String(analysisResult?.endpoints.length ?? 0)} accent="var(--accent)"
          icon={<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><rect x="1" y="1" width="11" height="11" rx="2" stroke="currentColor" strokeWidth="1.2"/></svg>} />
        <StatCard label="Parameters" value={String(
  analysisResult?.endpoints.reduce(
    (total, endpoint) => total + endpoint.parameters.length,
    0
  ) ?? 0
)} accent="#60a5fa"
          icon={<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M4 2v9M9 2v9M1 6.5h11" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/></svg>} />
        <StatCard label="Secrets Redacted" value={String(analysisResult?.security?.length ?? 0)} accent="#fb7185" sub="auto-protected"
          icon={<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M6.5 1L1.5 3v3.5C1.5 9.8 3.7 12.1 6.5 12.5 9.3 12.1 11.5 9.8 11.5 6.5V3L6.5 1z" stroke="currentColor" strokeWidth="1.2"/></svg>} />
      </div>
      <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
        <StatCard label="HTTP Methods" value={String(
  new Set(
    analysisResult?.endpoints.map((endpoint) => endpoint.method)
  ).size
)} accent="var(--green)"
          icon={<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M2 6.5h9M7.5 3l3.5 3.5L7.5 10" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/></svg>} />
        <StatCard label="Doc Confidence" value={`${analysisResult?.quality?.score ?? 0}%`} accent="var(--accent)"
          icon={<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><circle cx="6.5" cy="6.5" r="5.5" stroke="currentColor" strokeWidth="1.2"/><path d="M4 6.5l2 2 3-3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/></svg>} />
<StatCard
  label="Quality Score"
  value={String(analysisResult?.quality?.score ?? 0)}
  accent="#fbbf24"
  sub="/ 100"
         icon={<svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M6.5 1l1.5 3.2 3.5.5-2.5 2.4.6 3.4L6.5 9l-3.1 1.5.6-3.4L1.5 4.7l3.5-.5L6.5 1z" stroke="currentColor" strokeWidth="1.2"/></svg>} />
      </div>

      {ready ? (
  <>
<SecurityScan analysisResult={analysisResult} />
    <EndpointsTable
      activeIdx={docIdx}
      setActiveIdx={setDocIdx}
      analysisResult={analysisResult}
    />

    <DocViewer
      activeIdx={docIdx}
      setActiveIdx={setDocIdx}
      analysisResult={analysisResult}
    />

<ApiContext
  analysisResult={analysisResult}
  activeIdx={docIdx}
/>  </>
) : (
        <div className="panel" style={{ padding: "52px 24px", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", gap: 13 }}>
          <div style={{ width: 50, height: 50, borderRadius: 14, background: "var(--accent-dim)", border: "1px solid rgba(124,109,250,0.22)", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <svg width="22" height="22" viewBox="0 0 22 22" fill="none"><circle cx="11" cy="11" r="9" stroke="var(--accent)" strokeWidth="1.5"/><path d="M7.5 11l3 3 4-5" stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
          </div>
          <div style={{ fontFamily: "'Outfit', sans-serif", fontSize: 15, fontWeight: 600, color: "var(--text)" }}>Ready to analyze</div>
          <p style={{ fontSize: 13, color: "var(--text-2)", maxWidth: 290, margin: 0, lineHeight: 1.65 }}>
            Paste your API source code on the left and click <strong style={{ color: "var(--text)" }}>Analyze API</strong> to generate docs.
          </p>
        </div>
      )}
    </div>
  );
}

// ─── API Changes Tab ──────────────────────────────────────────────────────────

function ApiChangesView() {
  return (
    <div
      style={{
        maxWidth: 960,
        margin: "0 auto",
        padding: "36px 28px 80px",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 12,
          marginBottom: 22,
        }}
      >
        <h2
          style={{
            fontFamily: "'Outfit', sans-serif",
            fontSize: 21,
            fontWeight: 700,
            color: "var(--text)",
            letterSpacing: "-0.03em",
            margin: 0,
          }}
        >
          API Changes
        </h2>

        <span className="badge badge-green">
          No changes detected
        </span>
      </div>

      <div
        className="panel"
        style={{
          padding: "50px 30px",
          textAlign: "center",
        }}
      >
        <div
          style={{
            width: 42,
            height: 42,
            margin: "0 auto 16px",
            borderRadius: "50%",
            background: "var(--green-dim)",
            border: "1px solid rgba(16,185,129,0.2)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <svg
            width="18"
            height="18"
            viewBox="0 0 18 18"
            fill="none"
          >
            <circle
              cx="9"
              cy="9"
              r="7"
              stroke="#10b981"
              strokeWidth="1.4"
            />
            <path
              d="M5.5 9l2.2 2.2L12.5 6.5"
              stroke="#10b981"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>

        <div
          style={{
            fontSize: 15,
            fontWeight: 600,
            color: "var(--text)",
            marginBottom: 8,
          }}
        >
          No previous API version available
        </div>

        <p
          style={{
            maxWidth: 480,
            margin: "0 auto",
            fontSize: 12.5,
            color: "var(--text-2)",
            lineHeight: 1.7,
          }}
        >
          APIForge AI needs a previous API version to compare
          changes and detect breaking modifications.
        </p>

        <div
          style={{
            marginTop: 20,
            display: "inline-flex",
            alignItems: "center",
            gap: 7,
            padding: "8px 12px",
            borderRadius: "var(--radius-sm)",
            background: "var(--surface-2)",
            border: "1px solid var(--border)",
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 10.5,
            color: "var(--text-3)",
          }}
        >
          Change detection · Waiting for baseline
        </div>
      </div>
    </div>
  );
}

// ─── Settings Tab ─────────────────────────────────────────────────────────────

function SettingsView() {
  const settings = [
{ label: "AI Model", value: "Context-Aware Engine", badge: "badge-accent" },    { label: "Auto-redact secrets",     value: "Enabled",            badge: "badge-green" },
    { label: "Documentation format",    value: "OpenAPI 3.1 + Markdown" },
    { label: "Quality threshold",       value: "80 / 100" },
    { label: "Change detection",        value: "Enabled",            badge: "badge-green" },
    { label: "Export on analysis",      value: "Disabled",           badge: "badge-neutral" },
  ];
  return (
    <div style={{ maxWidth: 700, margin: "0 auto", padding: "36px 28px" }}>
      <h2 style={{ fontFamily: "'Outfit', sans-serif", fontSize: 21, fontWeight: 700, color: "var(--text)", letterSpacing: "-0.03em", marginBottom: 22 }}>Settings</h2>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {settings.map(s => (
          <div key={s.label} className="panel" style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 13, color: "var(--text-2)" }}>{s.label}</span>
            {s.badge
              ? <span className={`badge ${s.badge}`}>{s.value}</span>
              : <span className="font-mono" style={{ fontSize: 12, color: "var(--text)" }}>{s.value}</span>}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Export Bar ───────────────────────────────────────────────────────────────

function ExportBar({
  visible,
  analysisResult,
}: {
  visible: boolean;
  analysisResult: AnalysisResult | null;
}) {  if (!visible) return null;
  return (
    <div style={{
      position: "fixed", bottom: 0, left: 0, right: 0,
      background: "rgba(7,7,14,0.96)", backdropFilter: "blur(16px)",
      borderTop: "1px solid var(--border)", padding: "11px 28px",
      display: "flex", alignItems: "center", justifyContent: "center", gap: 10, zIndex: 50,
    }}>
      <span style={{ fontSize: 11.5, color: "var(--text-3)", marginRight: 6, fontFamily: "'JetBrains Mono', monospace" }}>Export:</span>
      {[
        { label: "Download Markdown", icon: "↓" },
        { label: "Export OpenAPI", icon: "⟲" },
        { label: "Copy Documentation", icon: "⎘" },
      ].map(b => (
<button
  key={b.label}
  className="btn-ghost"
  style={{ gap: 7 }}
  onClick={() => {
    if (b.label === "Download Markdown") {
      const markdown = analysisResult?.documentation
        ?.map(doc => `# ${doc.summary}
        
## Purpose
${doc.purpose}

## Parameters
${doc.parameters
  .map(p => `- ${p.name} (${p.type}, ${p.location})`)
  .join("\n")}

## Framework
${doc.framework}

## Data Source
${doc.data_source}

## Authentication
${doc.authentication}

## Typical Use Cases
${doc.use_cases.map(u => `- ${u}`).join("\n")}

## Context
${doc.context}`)
        .join("\n\n---\n\n") ?? "";

      const blob = new Blob([markdown], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = "apiforge-documentation.md";
      a.click();

      URL.revokeObjectURL(url);
    }if (b.label === "Copy Documentation") {
  const text = analysisResult?.documentation
    ?.map(
      (doc) => `${doc.summary}

Purpose:
${doc.purpose}

Parameters:
${doc.parameters
  .map((p) => `- ${p.name} (${p.type}, ${p.location})`)
  .join("\n")}

Framework: ${doc.framework}
Data Source: ${doc.data_source}
Authentication: ${doc.authentication}

Typical Use Cases:
${doc.use_cases.map((u) => `- ${u}`).join("\n")}

Context:
${doc.context}`
    )
    .join("\n\n---\n\n") ?? "";

  navigator.clipboard.writeText(text);
}
if (b.label === "Export OpenAPI") {
  const openapi = {
    openapi: "3.0.0",
    info: {
      title: "APIForge AI Generated API",
      version: "1.0.0",
      description: "API documentation generated by APIForge AI",
    },
    paths: Object.fromEntries(
      (analysisResult?.endpoints ?? []).map((ep) => [
        ep.path.replace(/<[^:>]+:/g, "{").replace(/>/g, "}"),
        {
          [ep.method.toLowerCase()]: {
            summary: `${ep.method} ${ep.path}`,
            operationId: ep.function,
            parameters: ep.parameters
              .filter((p) => p.location === "path" || p.location === "query")
              .map((p) => ({
                name: p.name,
                in: p.location,
                required: p.location === "path",
                schema: {
                  type:
                    p.type === "integer"
                      ? "integer"
                      : p.type === "number"
                      ? "number"
                      : p.type === "boolean"
                      ? "boolean"
                      : "string",
                },
              })),
          },
        },
      ])
    ),
  };

  const blob = new Blob(
    [JSON.stringify(openapi, null, 2)],
    { type: "application/json" }
  );

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");

  a.href = url;
  a.download = "apiforge-openapi.json";
  a.click();

  URL.revokeObjectURL(url);
}
  }}
>          <span style={{ fontSize: 13, lineHeight: 1 }}>{b.icon}</span>
          {b.label}
        </button>
      ))}
    </div>
  );
}

// ─── Analyzing Overlay ────────────────────────────────────────────────────────

function AnalyzingOverlay() {
  const steps = ["Scanning for secrets…", "Parsing endpoints…", "Mapping parameters…", "Inferring context…", "Generating AI docs…", "Scoring quality…"];
  const [stepIdx, setStepIdx] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setStepIdx(s => Math.min(s + 1, steps.length - 1)), 220);
    return () => clearInterval(t);
  }, []);
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(7,7,14,0.82)", backdropFilter: "blur(6px)", zIndex: 90, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div className="panel glow-accent animate-fade-up" style={{ padding: "36px 48px", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", gap: 16, minWidth: 320 }}>
        <div style={{ width: 44, height: 44, border: "2.5px solid var(--surface-3)", borderTop: "2.5px solid var(--accent)", borderRadius: "50%" }} className="animate-spin" />
        <div style={{ fontFamily: "'Outfit', sans-serif", fontSize: 16, fontWeight: 700, color: "var(--text)", letterSpacing: "-0.02em" }}>Analyzing API source code</div>
        <div className="font-mono" style={{ fontSize: 11.5, color: "var(--accent)", height: 18 }}>{steps[stepIdx]}</div>
        {/* Mini progress */}
        <div style={{ width: "100%", height: 2, background: "var(--surface-3)", borderRadius: 1, overflow: "hidden" }}>
          <div style={{ height: "100%", background: "linear-gradient(90deg, var(--accent), var(--purple))", width: `${((stepIdx + 1) / steps.length) * 100}%`, transition: "width 200ms ease", borderRadius: 1 }} />
        </div>
      </div>
    </div>
  );
}

// ─── Root App ─────────────────────────────────────────────────────────────────

export default function App() {
const [code, setCode] = useState("");  const [tab, setTab] = useState<NavTab>("Dashboard");
  const [analyzed, setAnalyzed] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [docIdx, setDocIdx] = useState(0);

  const [analysisResult, setAnalysisResult] =
  useState<AnalysisResult | null>(null);

  const [error, setError] = useState("");

  const handleAnalyze = async () => {
    console.log("ANALYZE BUTTON CLICKED");
    if (!code.trim() || analyzing) return;

  setAnalyzing(true);
  setError("");

  try {
    const response = await fetch("http://127.0.0.1:8000/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code }),
    });

    if (!response.ok) {
      throw new Error("Backend analysis failed");
    }

    const data: AnalysisResult = await response.json();
console.log("BACKEND DATA:", JSON.stringify(data, null, 2));    setAnalysisResult(data);
    setAnalyzed(true);
  } catch (err) {
    console.error(err);
    setError("Could not connect to APIForge backend.");
    setAnalyzed(false);
  } finally {
    setAnalyzing(false);
  }
};

  return (
    <div style={{ minHeight: "100vh", background: "var(--bg)" }}>
      <NavBar tab={tab} setTab={setTab} />

      {analyzing && <AnalyzingOverlay />}

      {tab === "Dashboard" && (
        <>
          <Hero onAnalyze={handleAnalyze} analyzing={analyzing} />
          <div style={{ maxWidth: 1440, margin: "0 auto", padding: "0 28px 80px" }}>
            <div className="workspace" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20, alignItems: "start" }}>
              {/* Left — sticky editor */}
              <div style={{ position: "sticky", top: 70, maxHeight: "calc(100vh - 90px)", display: "flex", flexDirection: "column" }}>
                <CodeEditor code={code} setCode={setCode} onAnalyze={handleAnalyze} analyzing={analyzing} />
              </div>
              {/* Right — analysis */}
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 14 }}>
                  <span style={{ fontFamily: "'Outfit', sans-serif", fontSize: 14, fontWeight: 700, color: "var(--text)", letterSpacing: "-0.02em" }}>API Analysis</span>
                  {analyzed
                    ? <span className="badge badge-green"><span className="animate-pulse-dot" style={{ width: 5, height: 5, borderRadius: "50%", background: "var(--green)", display: "inline-block" }}/>Complete</span>
                    : <span className="badge badge-neutral">Waiting for input</span>}
                </div>
                <AnalysisPanel ready={analyzed} docIdx={docIdx} setDocIdx={setDocIdx} analysisResult={analysisResult}/>
              </div>
            </div>
          </div>
<ExportBar
  visible={analyzed}
  analysisResult={analysisResult}
/>        </>
      )}

      {tab === "Documentation" && (
        <div style={{ maxWidth: 1440, margin: "0 auto", padding: "32px 28px 80px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 22 }}>
            <h2 style={{ fontFamily: "'Outfit', sans-serif", fontSize: 21, fontWeight: 700, color: "var(--text)", letterSpacing: "-0.03em", margin: 0 }}>Documentation</h2>
<span className="badge badge-accent">
  {analysisResult?.endpoints?.length ?? 0} endpoints
</span>          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 18, alignItems: "start" }}>
            <DocViewer activeIdx={docIdx} setActiveIdx={setDocIdx} analysisResult={analysisResult} />
            <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
              <QualityScore analysisResult={analysisResult} />
            </div>
          </div>
        </div>
      )}

      {tab === "API Changes" && <ApiChangesView />}
      {tab === "Settings" && <SettingsView />}
    </div>
  );
}
