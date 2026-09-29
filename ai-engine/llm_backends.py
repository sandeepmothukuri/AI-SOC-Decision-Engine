"""Enterprise Multi-Provider LLM Gateway for the AI SOC Engine.

Abstracted provider interface supporting:
- Ollama (local self-hosted model with JSON grammar constraints)
- Azure OpenAI (enterprise private deployment with response_format=json_object)
- OpenAI / OpenAI-compatible gateways (vLLM, LiteLLM, TensorRT-LLM)
- Groq (ultra-low latency LPU cloud inference with response_format=json_object)
- Anthropic Claude (Messages API with JSON system prompt constraints)
- AWS Bedrock (enterprise managed foundation models)
- OfflineBackend (deterministic rule engine fallback)
- ScriptedBackend (canned responses for automated test suites)
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

import httpx
from metrics import metrics_registry

logger = logging.getLogger(__name__)


class BackendError(Exception):
    """Raised when a backend cannot produce a result (down / timeout / malformed)."""


class BaseLLMBackend(ABC):
    """Abstract base class for all LLM inference providers."""

    @abstractmethod
    async def generate(self, prompt: str, schema: Optional[dict[str, Any]] = None) -> str:
        """Submit prompt and return stringified model response."""


class OllamaBackend(BaseLLMBackend):
    """Client for Ollama HTTP API with native JSON grammar constraint mode."""

    def __init__(
        self,
        host: str,
        model: str,
        temperature: float = 0.1,
        num_predict: int = 1024,
        timeout: float = 30.0,
    ):
        self.host = host.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.num_predict = num_predict
        self.timeout = timeout

    async def generate(self, prompt: str, schema: Optional[dict[str, Any]] = None) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",  # Forces Ollama grammar engine to emit strictly valid JSON
            "options": {"temperature": self.temperature, "num_predict": self.num_predict},
        }
        url = f"{self.host}/api/generate"
        started = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException as e:
            raise BackendError(f"Ollama timed out after {self.timeout}s") from e
        except httpx.HTTPStatusError as e:
            raise BackendError(f"Ollama HTTP {e.response.status_code}") from e
        except (httpx.ConnectError, httpx.TransportError) as e:
            raise BackendError(f"Ollama unreachable at {self.host}") from e

        elapsed = (time.monotonic() - started) * 1000
        text = data.get("response", "")
        if not text or not text.strip():
            raise BackendError("Ollama returned an empty response")

        # Track token telemetry
        prompt_tokens = data.get("prompt_eval_count", len(prompt) // 4)
        completion_tokens = data.get("eval_count", len(text) // 4)
        metrics_registry.record_tokens("ollama", self.model, prompt_tokens + completion_tokens)

        logger.debug("Ollama generated %d chars in %.0f ms", len(text), elapsed)
        return text


class AzureOpenAIBackend(BaseLLMBackend):
    """Client for Azure OpenAI Service with strict JSON object formatting."""

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        deployment: str,
        api_version: str = "2024-02-15-preview",
        temperature: float = 0.1,
        timeout: float = 30.0,
    ):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.deployment = deployment
        self.api_version = api_version
        self.temperature = temperature
        self.timeout = timeout

    async def generate(self, prompt: str, schema: Optional[dict[str, Any]] = None) -> str:
        url = (
            f"{self.endpoint}/openai/deployments/{self.deployment}/chat/completions"
            f"?api-version={self.api_version}"
        )
        headers = {
            "api-key": self.api_key,
            "Content-Type": "application/json",
        }
        payload = {
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are an expert SOC triage analysis engine. "
                        "You MUST respond ONLY with a single valid JSON object adhering to the specified schema."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
            "response_format": {"type": "json_object"},
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException as e:
            raise BackendError(f"Azure OpenAI timed out after {self.timeout}s") from e
        except httpx.HTTPStatusError as e:
            raise BackendError(
                f"Azure OpenAI HTTP {e.response.status_code}: {e.response.text}"
            ) from e
        except Exception as e:
            raise BackendError(f"Azure OpenAI error: {e}") from e

        choice = data.get("choices", [{}])[0]
        text = choice.get("message", {}).get("content", "")
        if not text:
            raise BackendError("Azure OpenAI returned empty choice")

        usage = data.get("usage", {})
        total_tokens = usage.get("total_tokens", len(prompt + text) // 4)
        metrics_registry.record_tokens("azure_openai", self.deployment, total_tokens)

        return text


class OpenAIBackend(BaseLLMBackend):
    """Client for OpenAI or any OpenAI-compatible API (vLLM, LiteLLM, LocalAI)."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o-mini",
        base_url: str = "https://api.openai.com/v1",
        temperature: float = 0.1,
        timeout: float = 30.0,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout

    async def generate(self, prompt: str, schema: Optional[dict[str, Any]] = None) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a SOC decision engine. Reply ONLY with valid JSON matching the schema.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
            "response_format": {"type": "json_object"},
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException as e:
            raise BackendError(f"OpenAI compatible endpoint timed out after {self.timeout}s") from e
        except httpx.HTTPStatusError as e:
            raise BackendError(
                f"OpenAI compatible HTTP {e.response.status_code}: {e.response.text}"
            ) from e
        except Exception as e:
            raise BackendError(f"OpenAI compatible error: {e}") from e

        text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        if not text:
            raise BackendError("OpenAI compatible endpoint returned empty content")

        usage = data.get("usage", {})
        total_tokens = usage.get("total_tokens", len(prompt + text) // 4)
        metrics_registry.record_tokens("openai", self.model, total_tokens)

        return text


class GroqBackend(BaseLLMBackend):
    """Client for Groq Cloud ultra-fast LPU inference."""

    def __init__(
        self,
        api_key: str,
        model: str = "llama-3.3-70b-versatile",
        temperature: float = 0.1,
        timeout: float = 15.0,
    ):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.timeout = timeout

    async def generate(self, prompt: str, schema: Optional[dict[str, Any]] = None) -> str:
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cyber security triage engine. Output strictly valid JSON without conversational wrapper.",
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
            "response_format": {"type": "json_object"},
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            raise BackendError(f"Groq API failure: {e}") from e

        text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        if not text:
            raise BackendError("Groq returned empty response")

        total_tokens = data.get("usage", {}).get("total_tokens", len(prompt + text) // 4)
        metrics_registry.record_tokens("groq", self.model, total_tokens)

        return text


class AnthropicBackend(BaseLLMBackend):
    """Client for Anthropic Claude Messages API."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-3-5-sonnet-20241022",
        temperature: float = 0.1,
        max_tokens: int = 1024,
        timeout: float = 30.0,
    ):
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

    async def generate(self, prompt: str, schema: Optional[dict[str, Any]] = None) -> str:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "system": (
                "You are an automated SOC incident triage engine. "
                "Output strictly a raw JSON object matching the requested schema. "
                "Do NOT wrap with backticks or conversational explanations."
            ),
            "messages": [{"role": "user", "content": prompt}],
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            raise BackendError(f"Anthropic API failure: {e}") from e

        blocks = data.get("content", [])
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        if not text:
            raise BackendError("Anthropic returned empty content")

        usage = data.get("usage", {})
        total_tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
        metrics_registry.record_tokens("anthropic", self.model, total_tokens)

        return text


class AWSBedrockBackend(BaseLLMBackend):
    """Client for AWS Bedrock Runtime Converse / InvokeModel API."""

    def __init__(
        self,
        model_id: str = "anthropic.claude-3-haiku-20240307-v1:0",
        region: str = "us-east-1",
        timeout: float = 30.0,
    ):
        self.model_id = model_id
        self.region = region
        self.timeout = timeout

    async def generate(self, prompt: str, schema: Optional[dict[str, Any]] = None) -> str:
        # Note: When boto3/aiobotocore is configured in environment, Bedrock runtime handles SigV4
        try:
            import boto3

            client = boto3.client("bedrock-runtime", region_name=self.region)
            native_request = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1024,
                "temperature": 0.1,
                "messages": [{"role": "user", "content": prompt}],
            }
            response = client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(native_request),
            )
            response_body = json.loads(response["body"].read())
            blocks = response_body.get("content", [])
            text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
            metrics_registry.record_tokens("bedrock", self.model_id, len(prompt + text) // 4)
            return text
        except ImportError:
            raise BackendError("boto3 is required for AWS Bedrock backend")
        except Exception as e:
            raise BackendError(f"AWS Bedrock error: {e}") from e


class OfflineBackend:
    """Deterministic, no-network analysis using the safety rule engine."""

    def __init__(self, safety_engine):
        self.safety = safety_engine

    async def analyze(self, alert: dict) -> dict[str, Any]:
        a = self.safety.assess(alert)
        return {
            "summary": a.summary,
            "severity": a.severity,
            "confidence": a.confidence,
            "rationale": a.rationale,
            "mitre_techniques": a.mitre_techniques,
            "recommended_action": a.recommended_action,
            "evidence": a.evidence,
            "verdict": a.verdict,
            "is_false_positive": (a.verdict == "CLOSE"),
        }


class ScriptedBackend:
    """Deterministic canned responses for tests (keyed on a marker string)."""

    def __init__(self, responses: dict[str, str]):
        self.responses = responses

    async def analyze(self, alert: dict) -> dict[str, Any]:
        raw = json.dumps(alert)
        for key, scripted in self.responses.items():
            if key in raw:
                from schemas import parse_model_json

                return parse_model_json(scripted)
        raise BackendError("no scripted response matched the alert")


def create_llm_backend(config: Any) -> Optional[BaseLLMBackend]:
    """Factory creating the appropriate LLM provider based on configuration."""
    backend_type = getattr(config, "backend", "ollama").lower()

    if backend_type == "offline":
        return None

    if backend_type == "ollama":
        return OllamaBackend(
            host=config.ollama_host,
            model=config.model_name,
            temperature=config.temperature,
            num_predict=config.num_predict,
            timeout=config.llm_timeout_seconds,
        )

    if backend_type == "azure_openai":
        return AzureOpenAIBackend(
            endpoint=config.raw.get("azure_openai", {}).get("endpoint", ""),
            api_key=config.raw.get("azure_openai", {}).get("api_key", ""),
            deployment=config.raw.get("azure_openai", {}).get("deployment", config.model_name),
            temperature=config.temperature,
            timeout=config.llm_timeout_seconds,
        )

    if backend_type == "openai":
        return OpenAIBackend(
            api_key=config.raw.get("openai", {}).get("api_key", ""),
            model=config.model_name,
            base_url=config.raw.get("openai", {}).get("base_url", "https://api.openai.com/v1"),
            temperature=config.temperature,
            timeout=config.llm_timeout_seconds,
        )

    if backend_type == "groq":
        return GroqBackend(
            api_key=config.raw.get("groq", {}).get("api_key", ""),
            model=config.model_name or "llama-3.3-70b-versatile",
            temperature=config.temperature,
            timeout=config.llm_timeout_seconds,
        )

    if backend_type == "anthropic":
        return AnthropicBackend(
            api_key=config.raw.get("anthropic", {}).get("api_key", ""),
            model=config.model_name or "claude-3-5-sonnet-20241022",
            temperature=config.temperature,
            timeout=config.llm_timeout_seconds,
        )

    if backend_type == "aws_bedrock":
        return AWSBedrockBackend(
            model_id=config.model_name,
            region=config.raw.get("aws_bedrock", {}).get("region", "us-east-1"),
            timeout=config.llm_timeout_seconds,
        )

    logger.warning("Unrecognized backend '%s', defaulting to Ollama", backend_type)
    return OllamaBackend(
        host=config.ollama_host,
        model=config.model_name,
        temperature=config.temperature,
        num_predict=config.num_predict,
        timeout=config.llm_timeout_seconds,
    )
