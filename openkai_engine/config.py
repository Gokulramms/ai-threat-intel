"""Enterprise Configuration and Settings Management for OpenKai."""

import os
from typing import Optional, List, Dict, Any
from pathlib import Path

# Load .env file automatically
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.exists():
        load_dotenv(dotenv_path=env_path, override=True)
except ImportError:
    pass

def _get_clean_env(key: str, default: Optional[str] = None) -> Optional[str]:
    """Retrieve environment variable, stripping inline comments and whitespace."""
    val = os.getenv(key)
    if val is None:
        return default
    # Strip inline comments like # comment
    if "#" in val:
        val = val.split("#")[0]
    val = val.strip().strip('"').strip("'")
    return val if val else default

class Settings:
    # Environment & Logging
    ENVIRONMENT: str = _get_clean_env("ENVIRONMENT", "production")
    DEBUG: bool = _get_clean_env("DEBUG", "false").lower() in ("true", "1", "yes")
    LOG_LEVEL: str = _get_clean_env("LOG_LEVEL", "INFO").upper()

    # Database
    DATABASE_URL: str = _get_clean_env(
        "DATABASE_URL",
        "sqlite+aiosqlite:///openkai_data.db"
    )

    # Security & RBAC
    SECRET_KEY: str = _get_clean_env("OPENKAI_SECRET_KEY", "openkai-enterprise-default-secret-change-in-prod-7f9a8b1c")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(_get_clean_env("ACCESS_TOKEN_EXPIRE_MINUTES", "720"))
    ADMIN_USERNAME: str = _get_clean_env("OPENKAI_ADMIN_USER", "socadmin")
    ADMIN_PASSWORD: str = _get_clean_env("OPENKAI_ADMIN_PASS", "OpenKai@SOC2026!")

    # CrowdStrike Falcon Integration
    CROWDSTRIKE_CLIENT_ID: Optional[str] = _get_clean_env("CROWDSTRIKE_CLIENT_ID")
    CROWDSTRIKE_CLIENT_SECRET: Optional[str] = _get_clean_env("CROWDSTRIKE_CLIENT_SECRET")
    CROWDSTRIKE_BASE_URL: str = _get_clean_env("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")

    # Elastic SIEM Integration
    ELASTIC_URL: Optional[str] = _get_clean_env("ELASTIC_URL")
    ELASTIC_API_KEY: Optional[str] = _get_clean_env("ELASTIC_API_KEY")
    ELASTIC_USERNAME: Optional[str] = _get_clean_env("ELASTIC_USERNAME")
    ELASTIC_PASSWORD: Optional[str] = _get_clean_env("ELASTIC_PASSWORD")
    ELASTIC_INDEX: str = _get_clean_env("ELASTIC_INDEX", "logs-*,security-*,audit-*")

    # Threat Intelligence Feeds & Keys
    VIRUSTOTAL_API_KEY: Optional[str] = _get_clean_env("VIRUSTOTAL_API_KEY")
    ABUSEIPDB_API_KEY: Optional[str] = _get_clean_env("ABUSEIPDB_API_KEY")
    OTX_API_KEY: Optional[str] = _get_clean_env("OTX_API_KEY")
    NVD_API_KEY: Optional[str] = _get_clean_env("NVD_API_KEY")
    ABUSE_CH_API_KEY: Optional[str] = _get_clean_env("ABUSE_CH_API_KEY")

    # AI / LLM Configuration (Default: Google Gemini AI)
    LLM_PROVIDER: str = _get_clean_env("LLM_PROVIDER", "gemini")  # gemini | ollama | anthropic | openai | mock
    GEMINI_API_KEY: Optional[str] = _get_clean_env("GEMINI_API_KEY")
    GEMINI_MODEL: str = _get_clean_env("GEMINI_MODEL", "gemini-2.5-flash-lite")
    OLLAMA_BASE_URL: str = _get_clean_env("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = _get_clean_env("OLLAMA_MODEL", "llama3:8b")
    OPENAI_API_KEY: Optional[str] = _get_clean_env("OPENAI_API_KEY")
    OPENAI_MODEL: str = _get_clean_env("OPENAI_MODEL", "gpt-4o-mini")
    ANTHROPIC_API_KEY: Optional[str] = _get_clean_env("ANTHROPIC_API_KEY")
    ANTHROPIC_MODEL: str = _get_clean_env("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")

    # Webhook Notifications
    SLACK_WEBHOOK_URL: Optional[str] = _get_clean_env("SLACK_WEBHOOK_URL")
    TEAMS_WEBHOOK_URL: Optional[str] = _get_clean_env("TEAMS_WEBHOOK_URL")
    DISCORD_WEBHOOK_URL: Optional[str] = _get_clean_env("DISCORD_WEBHOOK_URL")
    SMTP_HOST: Optional[str] = _get_clean_env("SMTP_HOST")
    SMTP_PORT: int = int(_get_clean_env("SMTP_PORT", "587"))
    SMTP_USER: Optional[str] = _get_clean_env("SMTP_USER")
    SMTP_PASSWORD: Optional[str] = _get_clean_env("SMTP_PASSWORD")
    ALERT_EMAIL_TO: Optional[str] = _get_clean_env("ALERT_EMAIL_TO")

    # Scheduler Intervals (in minutes)
    TI_SYNC_INTERVAL_MINUTES: int = int(_get_clean_env("TI_SYNC_INTERVAL_MINUTES", "60"))
    CROWDSTRIKE_SYNC_INTERVAL_MINUTES: int = int(_get_clean_env("CROWDSTRIKE_SYNC_INTERVAL_MINUTES", "30"))
    ELASTIC_SYNC_INTERVAL_MINUTES: int = int(_get_clean_env("ELASTIC_SYNC_INTERVAL_MINUTES", "15"))

    def get_sanitized_summary(self) -> Dict[str, Any]:
        """Return configuration with all secrets and keys safely masked."""
        def mask(val: Optional[str]) -> str:
            if not val:
                return "Not Configured"
            if len(val) <= 6:
                return "******"
            return val[:3] + "..." + val[-3:]

        return {
            "environment": self.ENVIRONMENT,
            "database": "Configured (SQLite/Postgres)",
            "crowdstrike": {
                "base_url": self.CROWDSTRIKE_BASE_URL,
                "client_id": mask(self.CROWDSTRIKE_CLIENT_ID),
                "configured": bool(self.CROWDSTRIKE_CLIENT_ID and self.CROWDSTRIKE_CLIENT_SECRET),
            },
            "elastic_siem": {
                "url": self.ELASTIC_URL or "Not Configured",
                "index_pattern": self.ELASTIC_INDEX,
                "configured": bool(self.ELASTIC_URL and (self.ELASTIC_API_KEY or self.ELASTIC_PASSWORD)),
            },
            "threat_intel_keys": {
                "virustotal": mask(self.VIRUSTOTAL_API_KEY),
                "abuseipdb": mask(self.ABUSEIPDB_API_KEY),
                "alienvault_otx": mask(self.OTX_API_KEY),
                "nvd": mask(self.NVD_API_KEY),
            },
            "ai_engine": {
                "provider": self.LLM_PROVIDER,
                "gemini_configured": bool(self.GEMINI_API_KEY),
                "gemini_model": self.GEMINI_MODEL,
                "ollama_url": self.OLLAMA_BASE_URL,
                "ollama_model": self.OLLAMA_MODEL,
                "openai_configured": bool(self.OPENAI_API_KEY),
                "anthropic_configured": bool(self.ANTHROPIC_API_KEY),
            },
            "notifications": {
                "slack_configured": bool(self.SLACK_WEBHOOK_URL),
                "teams_configured": bool(self.TEAMS_WEBHOOK_URL),
                "discord_configured": bool(self.DISCORD_WEBHOOK_URL),
                "email_configured": bool(self.SMTP_HOST and self.ALERT_EMAIL_TO),
            }
        }

settings = Settings()
