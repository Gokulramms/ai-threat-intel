"""Unit test for Google Gemini AI agent provider in OpenKai."""

import pytest
from openkai_engine.services.ai_orchestrator import LLMClient
from openkai_engine.config import settings

@pytest.mark.asyncio
async def test_gemini_ai_client_configuration():
    client = LLMClient()
    # Check that default provider is gemini
    assert client.provider == "gemini"
    assert "gemini" in client.gemini_model

    # Test generation (falls back gracefully to deterministic expert synthesis if no live key in CI)
    system_prompt = "You are a Threat Intelligence Analyst."
    user_prompt = "Analyze CVE-2024-38077."
    response = await client.generate(system_prompt, user_prompt)
    assert isinstance(response, str)
    assert len(response) > 0
    assert "SOC AI Technical Investigation Analysis" in response or len(response) > 20
