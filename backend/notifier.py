"""
VulnScope v2 - Notifier
Email and webhook alert notifications for critical CVEs
"""
import json
import asyncio
import smtplib
import httpx
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone
from database import get_db

# Configuration (set via environment or config file)
NOTIFY_CONFIG = {
    "email": {
        "enabled": False,
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_pass": "",
        "from_addr": "",
        "to_addrs": [],
    },
    "webhook": {
        "enabled": False,
        "urls": [],  # List of webhook URLs
        "discord": "",  # Discord webhook URL
        "slack": "",  # Slack webhook URL
        "teams": "",  # Teams webhook URL
    },
    "thresholds": {
        "min_severity": "HIGH",
        "min_cvss": 7.0,
        "min_epss": 0.5,
        "min_risk_score": 6.0,
        "notify_cisa_kev": True,
        "notify_ransomware": True,
        "notify_exploit_available": True,
    },
}


def load_config():
    """Load notifier config from environment variables"""
    import os
    
    # Email
    if os.environ.get("VULNSCOPE_SMTP_HOST"):
        NOTIFY_CONFIG["email"]["enabled"] = True
        NOTIFY_CONFIG["email"]["smtp_host"] = os.environ["VULNSCOPE_SMTP_HOST"]
        NOTIFY_CONFIG["email"]["smtp_port"] = int(os.environ.get("VULNSCOPE_SMTP_PORT", 587))
        NOTIFY_CONFIG["email"]["smtp_user"] = os.environ.get("VULNSCOPE_SMTP_USER", "")
        NOTIFY_CONFIG["email"]["smtp_pass"] = os.environ.get("VULNSCOPE_SMTP_PASS", "")
        NOTIFY_CONFIG["email"]["from_addr"] = os.environ.get("VULNSCOPE_FROM_ADDR", "")
        NOTIFY_CONFIG["email"]["to_addrs"] = os.environ.get("VULNSCOPE_TO_ADDRS", "").split(",")

    # Webhooks
    if os.environ.get("VULNSCOPE_DISCORD_WEBHOOK"):
        NOTIFY_CONFIG["webhook"]["enabled"] = True
        NOTIFY_CONFIG["webhook"]["discord"] = os.environ["VULNSCOPE_DISCORD_WEBHOOK"]
    if os.environ.get("VULNSCOPE_SLACK_WEBHOOK"):
        NOTIFY_CONFIG["webhook"]["enabled"] = True
        NOTIFY_CONFIG["webhook"]["slack"] = os.environ["VULNSCOPE_SLACK_WEBHOOK"]
    if os.environ.get("VULNSCOPE_TEAMS_WEBHOOK"):
        NOTIFY_CONFIG["webhook"]["enabled"] = True
        NOTIFY_CONFIG["webhook"]["teams"] = os.environ["VULNSCOPE_TEAMS_WEBHOOK"]


async def should_notify(cve_data: dict, risk_data: dict = None) -> tuple:
    """Check if a CVE meets notification thresholds"""
    config = NOTIFY_CONFIG["thresholds"]
    reasons = []

    severity = cve_data.get("severity", "UNKNOWN")
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_sev = severity_order.get(config["min_severity"], 3)

    if severity_order.get(severity, 0) >= min_sev:
        reasons.append(f"Severity: {severity}")

    cvss = cve_data.get("cvss_score") or 0
    if cvss >= config["min_cvss"]:
        reasons.append(f"CVSS: {cvss}")

    epss = cve_data.get("epss_score") or 0
    if epss >= config["min_epss"]:
        reasons.append(f"EPSS: {epss} (top {cve_data.get('epss_percentile', 0)}%)")

    if risk_data and risk_data.get("vulnscope_risk_score", 0) >= config["min_risk_score"]:
        reasons.append(f"Risk Score: {risk_data['vulnscope_risk_score']}")

    return bool(reasons), reasons


async def send_discord_webhook(cve_data: dict, risk_data: dict = None):
    """Send alert to Discord webhook"""
    url = NOTIFY_CONFIG["webhook"]["discord"]
    if not url:
        return

    severity = cve_data.get("severity", "UNKNOWN")
    color_map = {"CRITICAL": 0xEF4444, "HIGH": 0xF59E0B, "MEDIUM": 0x3B82F6, "LOW": 0x22C55E}
    color = color_map.get(severity, 0x808080)

    embed = {
        "title": f"🚨 {cve_data['cve_id']} - {severity}",
        "description": (cve_data.get("description", "") or "No description")[:2000],
        "color": color,
        "fields": [
            {"name": "CVSS Score", "value": str(cve_data.get("cvss_score") or "N/A"), "inline": True},
            {"name": "EPSS", "value": f"{cve_data.get('epss_score', 0):.4f}", "inline": True},
            {"name": "Vendor", "value": cve_data.get("vendor") or "Unknown", "inline": True},
            {"name": "Product", "value": cve_data.get("product") or "Unknown", "inline": True},
        ],
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_data['cve_id']}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if risk_data:
        embed["fields"].append({
            "name": "🔮 VulnScope Risk",
            "value": f"{risk_data['vulnscope_risk_score']}/10 ({risk_data['vulnscope_risk_level']})",
            "inline": True,
        })

    payload = {"embeds": [embed]}

    try:
        async with httpx.AsyncClient() as client:
            await client.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"[Notifier] Discord webhook failed: {e}")


async def send_slack_webhook(cve_data: dict, risk_data: dict = None):
    """Send alert to Slack webhook"""
    url = NOTIFY_CONFIG["webhook"]["slack"]
    if not url:
        return

    severity = cve_data.get("severity", "UNKNOWN")
    emoji = {"CRITICAL": ":red_circle:", "HIGH": ":warning:", "MEDIUM": ":large_blue_circle:"}
    icon = emoji.get(severity, ":white_circle:")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{icon} {cve_data['cve_id']} - {severity}"}
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{cve_data.get('vendor', 'Unknown')} - {cve_data.get('product', 'Unknown')}*\n{(cve_data.get('description', '') or 'No description')[:500]}"
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*CVSS:* {cve_data.get('cvss_score') or 'N/A'}"},
                {"type": "mrkdwn", "text": f"*EPSS:* {cve_data.get('epss_score', 0):.4f}"},
            ]
        },
    ]

    if risk_data:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"🔮 *VulnScope Risk:* {risk_data['vulnscope_risk_score']}/10 ({risk_data['vulnscope_risk_level']})"}
        })

    try:
        async with httpx.AsyncClient() as client:
            await client.post(url, json={"blocks": blocks}, timeout=10)
    except Exception as e:
        print(f"[Notifier] Slack webhook failed: {e}")


async def send_email_alert(cve_data: dict, risk_data: dict = None):
    """Send email alert"""
    config = NOTIFY_CONFIG["email"]
    if not config["enabled"] or not config["to_addrs"]:
        return

    severity = cve_data.get("severity", "UNKNOWN")
    subject = f"[VulnScope] {severity} - {cve_data['cve_id']}"

    html = f"""
    <html><body style="font-family: Arial, sans-serif; padding: 20px;">
      <h2 style="color: #ef4444;">{severity} Vulnerability Alert</h2>
      <h3>{cve_data['cve_id']}</h3>
      <p><strong>Vendor:</strong> {cve_data.get('vendor', 'Unknown')}</p>
      <p><strong>Product:</strong> {cve_data.get('product', 'Unknown')}</p>
      <p><strong>CVSS:</strong> {cve_data.get('cvss_score', 'N/A')}</p>
      <p><strong>EPSS:</strong> {cve_data.get('epss_score', 0):.4f}</p>
      <p>{cve_data.get('description', '')[:500]}</p>
      {"<p style='color: #ef4444;'><strong>ACTIVELY EXPLOITED</strong></p>" if cve_data.get("is_cisa_kev") else ""}
      <hr>
      <p><small>Alert generated by VulnScope v2</small></p>
    </body></html>
    """

    msg = MIMEMultipart()
    msg["From"] = config["from_addr"]
    msg["To"] = ", ".join(config["to_addrs"])
    msg["Subject"] = subject
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(config["smtp_host"], config["smtp_port"], timeout=10) as server:
            server.starttls()
            if config["smtp_user"]:
                server.login(config["smtp_user"], config["smtp_pass"])
            server.send_message(msg)
    except Exception as e:
        print(f"[Notifier] Email failed: {e}")


async def process_alert(cve_data: dict, risk_data: dict = None):
    """Process a CVE alert through all configured channels"""
    should, reasons = await should_notify(cve_data, risk_data)
    if not should:
        return

    print(f"[Notifier] Alert: {cve_data['cve_id']} ({', '.join(reasons)})")

    # Send to all configured channels
    await send_discord_webhook(cve_data, risk_data)
    await send_slack_webhook(cve_data, risk_data)
    # Email disabled by default (needs SMTP config)


async def notification_loop():
    """Background notification checker"""
    load_config()
    print("[Notifier] Notification system initialized")

    while True:
        if not NOTIFY_CONFIG["webhook"]["enabled"] and not NOTIFY_CONFIG["email"]["enabled"]:
            await asyncio.sleep(3600)
            continue

        try:
            db = await get_db()
            # Get recent critical CVEs with high EPSS
            rows = await db.execute("""
                SELECT * FROM cves
                WHERE severity = 'CRITICAL'
                AND epss_score > 0.5
                AND cve_id NOT IN (
                    SELECT cve_id FROM notification_sent WHERE sent_at > datetime('now', '-1 day')
                )
                ORDER BY published_date DESC
                LIMIT 10
            """)
            cves = [dict(r) for r in await rows.fetchall()]

            for cve in cves:
                await process_alert(cve)
                # Mark as sent
                try:
                    await db.execute("""
                        INSERT INTO notification_sent (cve_id, channel, sent_at)
                        VALUES (?, 'all', datetime('now'))
                    """, (cve["cve_id"],))
                except:
                    pass

            await db.commit()
            await db.close()
        except Exception as e:
            print(f"[Notifier] Error: {e}")

        await asyncio.sleep(300)  # Check every 5 minutes
