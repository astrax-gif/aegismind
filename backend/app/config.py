from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=("../.env", ".env"), extra="ignore")

    # Bifrost
    bifrost_base_url: str = "http://localhost:8080"
    bifrost_virtual_key: str | None = None
    cloud_model: str = "openai/gpt-4o-mini"
    cloud_fallbacks_csv: str = "anthropic/claude-3-5-haiku-latest"
    local_model: str = "ollama/llama3.1:8b"

    # Tavily
    tavily_api_key: str = ""

    # Budgets (USD)
    run_budget_usd: float = 0.25
    global_budget_usd: float = 5.00

    # Resilience
    breaker_failure_threshold: int = 3
    breaker_cooldown_s: float = 30.0
    request_timeout_s: float = 60.0
    max_retries: int = 1
    chaos_cloud_failure_rate: float = 0.0   # demo: inject cloud failures

    # Paths
    demo_dir: Path = Path(__file__).resolve().parents[2] / "demo_data" / "labs"

    @property
    def cloud_fallbacks(self) -> list[str]:
        return [m.strip() for m in self.cloud_fallbacks_csv.split(",") if m.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()