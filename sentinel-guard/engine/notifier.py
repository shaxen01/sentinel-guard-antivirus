"""
Sentinel Guard — Notifier
Sends threat alerts via multiple configured channels
"""
import os
import sys
import json
import time
import smtplib
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from utils.logger import get_logger

logger = get_logger(__name__)


class Notifier:
    """Sends threat alerts via multiple channels (Email, Webhook, Telegram, Discord)."""

    def __init__(self, config: dict = None):
        self.config = config or {}

    def configure(self, config: dict):
        """Set or update notification channels configuration."""
        if not isinstance(config, dict):
            logger.warning("Invalid configuration type. Expected dict.")
            return
        self.config.update(config)
        logger.info("Notifier configuration updated.")

    def _send_email(self, to: str, subject: str, body: str) -> bool:
        """Send email alert using smtplib."""
        host = self.config.get("SMTP_HOST") or os.environ.get("SMTP_HOST")
        port_str = self.config.get("SMTP_PORT") or os.environ.get("SMTP_PORT") or "587"
        user = self.config.get("SMTP_USER") or os.environ.get("SMTP_USER")
        password = self.config.get("SMTP_PASS") or os.environ.get("SMTP_PASS")
        sender = self.config.get("ALERT_EMAIL") or os.environ.get("ALERT_EMAIL")

        if not (host and user and password and sender and to):
            logger.debug("Email notification skipped: missing SMTP configuration details.")
            return False

        try:
            port = int(port_str)
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = to
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain', 'utf-8'))

            logger.info(f"Connecting to SMTP server {host}:{port} to send alert...")
            if port == 465:
                server = smtplib.SMTP_SSL(host, port, timeout=10)
            else:
                server = smtplib.SMTP(host, port, timeout=10)
                server.starttls()

            server.login(user, password)
            server.send_message(msg)
            server.quit()
            logger.info(f"📧 Alert email successfully sent to {to}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False

    def _send_webhook(self, url: str, payload: dict) -> bool:
        """POST JSON payload to a webhook URL."""
        if not url:
            logger.debug("Webhook notification skipped: empty URL.")
            return False

        try:
            data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(
                url,
                data=data,
                headers={'Content-Type': 'application/json', 'User-Agent': 'Sentinel-Guard-Notifier'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                status = response.status
                if 200 <= status < 300:
                    logger.info(f"🔗 Successfully posted alert payload to webhook: {url}")
                    return True
                else:
                    logger.warning(f"Webhook POST to {url} returned status code {status}")
                    return False
        except urllib.error.URLError as e:
            logger.error(f"URLError when sending to webhook {url}: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to send webhook to {url}: {e}")
            return False

    def _send_telegram(self, message: str) -> bool:
        """Send alert via Telegram Bot API."""
        token = self.config.get("TELEGRAM_BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN")
        chat_id = self.config.get("TELEGRAM_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID")

        if not (token and chat_id):
            logger.debug("Telegram notification skipped: missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID.")
            return False

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }

        logger.info("Sending alert to Telegram channel...")
        return self._send_webhook(url, payload)

    def _send_discord(self, message: str) -> bool:
        """Send alert via Discord Webhook."""
        webhook_url = self.config.get("DISCORD_WEBHOOK_URL") or os.environ.get("DISCORD_WEBHOOK_URL")

        if not webhook_url:
            logger.debug("Discord notification skipped: missing DISCORD_WEBHOOK_URL.")
            return False

        payload = {
            "content": message
        }

        logger.info("Sending alert to Discord channel...")
        return self._send_webhook(webhook_url, payload)

    def send_alert(self, title: str, message: str, severity: str) -> bool:
        """Send threat alert via all configured channels."""
        logger.info(f"Broadcasting threat alert: [{severity}] {title}")
        success_any = False
        attempts = 0

        # 1. Email Channel
        email_to = self.config.get("ALERT_EMAIL") or os.environ.get("ALERT_EMAIL")
        if email_to:
            attempts += 1
            subject = f"🛡️ Sentinel Guard: [{severity}] {title}"
            body = f"Severity: {severity}\nTime: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n{message}"
            if self._send_email(email_to, subject, body):
                success_any = True

        # 2. Generic Webhook Channel
        webhook_url = self.config.get("WEBHOOK_URL") or os.environ.get("WEBHOOK_URL")
        if webhook_url:
            attempts += 1
            payload = {
                "event": "sentinel_guard_alert",
                "title": title,
                "message": message,
                "severity": severity,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            if self._send_webhook(webhook_url, payload):
                success_any = True

        # 3. Telegram Channel
        telegram_token = self.config.get("TELEGRAM_BOT_TOKEN") or os.environ.get("TELEGRAM_BOT_TOKEN")
        telegram_chat_id = self.config.get("TELEGRAM_CHAT_ID") or os.environ.get("TELEGRAM_CHAT_ID")
        if telegram_token and telegram_chat_id:
            attempts += 1
            formatted_msg = f"⚠️ *Sentinel Guard Alert*\n\n*Title:* {title}\n*Severity:* {severity}\n*Time:* {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n{message}"
            if self._send_telegram(formatted_msg):
                success_any = True

        # 4. Discord Channel
        discord_url = self.config.get("DISCORD_WEBHOOK_URL") or os.environ.get("DISCORD_WEBHOOK_URL")
        if discord_url:
            attempts += 1
            formatted_msg = f"⚠️ **Sentinel Guard Alert**\n\n**Title:** {title}\n**Severity:** {severity}\n**Time:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n{message}"
            if self._send_discord(formatted_msg):
                success_any = True

        if attempts == 0:
            logger.warning("No notification channels are configured. Alert transmission skipped.")
            return False

        return success_any
