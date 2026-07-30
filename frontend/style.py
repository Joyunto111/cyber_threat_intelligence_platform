"""Cybersecurity Dashboard Styling and Custom CSS."""

def get_custom_css() -> str:
    return """
    <style>
        /* Modern Cybersecurity Dark Theme */
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');
        
        :root {
            --bg-dark: #0b0f19;
            --bg-card: #111827;
            --border-card: #1f2937;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --risk-critical: #ef4444;
            --risk-high: #f97316;
            --risk-medium: #eab308;
            --risk-low: #10b981;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }

        .main {
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
        }

        /* Metric Card */
        .metric-card {
            background: linear-gradient(135deg, #111827 0%, #1e293b 100%);
            border: 1px solid #1f2937;
            border-radius: 10px;
            padding: 18px 20px;
            margin-bottom: 12px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
            transition: transform 0.2s, border-color 0.2s;
        }
        .metric-card:hover {
            transform: translateY(-2px);
            border-color: #3b82f6;
        }
        .metric-title {
            font-size: 0.82rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 6px;
            font-weight: 600;
        }
        .metric-value {
            font-size: 1.85rem;
            font-weight: 700;
            color: #ffffff;
            font-family: 'JetBrains Mono', monospace;
        }

        /* Risk Badges */
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 0.78rem;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            font-family: 'JetBrains Mono', monospace;
        }
        .badge-critical {
            background-color: rgba(239, 68, 68, 0.2);
            color: #f87171;
            border: 1px solid #ef4444;
        }
        .badge-high {
            background-color: rgba(249, 115, 22, 0.2);
            color: #fb923c;
            border: 1px solid #f97316;
        }
        .badge-medium {
            background-color: rgba(234, 179, 8, 0.2);
            color: #facc15;
            border: 1px solid #eab308;
        }
        .badge-low {
            background-color: rgba(16, 185, 129, 0.2);
            color: #34d399;
            border: 1px solid #10b981;
        }
        .badge-unknown {
            background-color: rgba(156, 163, 175, 0.2);
            color: #9ca3af;
            border: 1px solid #4b5563;
        }

        /* Code and defanged text */
        .defanged-box {
            background-color: #0d1117;
            border: 1px solid #21262d;
            border-radius: 6px;
            padding: 8px 12px;
            font-family: 'JetBrains Mono', monospace;
            color: #58a6ff;
            font-size: 0.88rem;
            word-break: break-all;
        }

        /* Narrative Summary Box */
        .summary-box {
            background-color: #0f172a;
            border-left: 4px solid #0284c7;
            padding: 16px 20px;
            border-radius: 0 8px 8px 0;
            margin: 14px 0;
            color: #e2e8f0;
            line-height: 1.6;
        }

        /* Sidebar Styling */
        section[data-testid="stSidebar"] {
            background-color: #090d16 !important;
            border-right: 1px solid #1f2937;
        }

        /* Headings */
        h1, h2, h3 {
            color: #f8fafc !important;
            font-weight: 700 !important;
        }
    </style>
    """
