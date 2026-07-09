import json
import os
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from collections import deque

from lib.core.logger import get_logger
from lib.core.config import get_config
from lib.core.secrets import get_secret
from lib.ui import print_status


logger = get_logger(__name__)
config = get_config()

# Cerebras supported models with limits (Model, RPM, TPM, TPH, TPD)
CEREBRAS_MODELS = [
    {"name": "gpt-oss-120b", "rpm": 5, "tpm": 30000, "tph": 1000000, "tpd": 1000000},
    {"name": "zai-glm-4.7", "rpm": 5, "tpm": 30000, "tph": 1000000, "tpd": 1000000},
    {"name": "gemma-4-31b", "rpm": 5, "tpm": 30000, "tph": 1000000, "tpd": 1000000},
]

# Groq supported models with limits (Model, RPM, RPD, TPM, TPD)
GROQ_MODELS = [
    {"name": "meta-llama/llama-4-scout-17b-16e-instruct", "rpm": 30, "rpd": 1000, "tpm": 30000, "tpd": 500000},
    {"name": "groq/compound", "rpm": 30, "rpd": 250, "tpm": 70000, "tpd": 500000},
    {"name": "groq/compound-mini", "rpm": 30, "rpd": 250, "tpm": 70000, "tpd": 500000},
]


class RateLimiter:
    def __init__(self, rpm: int = 5):
        self.rpm = rpm
        self.request_timestamps = deque()

    def acquire(self):
        now = time.time()
        # Remove timestamps older than 1 minute
        while self.request_timestamps and (now - self.request_timestamps[0]) > 60:
            self.request_timestamps.popleft()
        # If we've reached the limit, wait
        if len(self.request_timestamps) >= self.rpm:
            wait_time = 60 - (now - self.request_timestamps[0])
            if wait_time > 0:
                logger.debug(f"Rate limit reached, waiting {wait_time:.2f}s")
                time.sleep(wait_time)
            # Remove old timestamps again after waiting
            while self.request_timestamps and (time.time() - self.request_timestamps[0]) > 60:
                self.request_timestamps.popleft()
        self.request_timestamps.append(time.time())


@dataclass
class LLMConfig:
    provider: str = "none"  # "none", "openai", "anthropic", "ollama", "cerebras", "groq"
    api_key: Optional[str] = None
    model: str = "gpt-oss-120b"
    temperature: float = 0.2
    max_tokens: int = 1000
    base_url: Optional[str] = None  # For Ollama or custom endpoints


class LLMProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None, json_schema: Optional[Dict[str, Any]] = None, quiet: bool = False) -> Dict[str, Any]:
        pass


class NoneProvider(LLMProvider):
    def generate(self, prompt: str, system_prompt: Optional[str] = None, json_schema: Optional[Dict[str, Any]] = None, quiet: bool = False) -> Dict[str, Any]:
        raise ValueError("LLM provider is disabled")


class OpenAIProvider(LLMProvider):
    def __init__(self, llm_config: LLMConfig):
        self.config = llm_config
        try:
            import openai
            self.client = openai.OpenAI(
                api_key=llm_config.api_key,
                base_url=llm_config.base_url
            )
        except ImportError:
            raise ImportError("openai package not installed. Install with: pip install openai")

    def generate(self, prompt: str, system_prompt: Optional[str] = None, json_schema: Optional[Dict[str, Any]] = None, quiet: bool = False) -> Dict[str, Any]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens
        }

        if json_schema:
            kwargs["response_format"] = {"type": "json_schema", "json_schema": {"name": "response", "strict": True, "schema": json_schema}}

        try:
            response = self.client.chat.completions.create(**kwargs)
            content = response.choices[0].message.content
            if json_schema:
                return json.loads(content)
            return {"content": content}
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise


class AnthropicProvider(LLMProvider):
    def __init__(self, llm_config: LLMConfig):
        self.config = llm_config
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=llm_config.api_key)
        except ImportError:
            raise ImportError("anthropic package not installed. Install with: pip install anthropic")

    def generate(self, prompt: str, system_prompt: Optional[str] = None, json_schema: Optional[Dict[str, Any]] = None, quiet: bool = False) -> Dict[str, Any]:
        messages = [{"role": "user", "content": prompt}]

        kwargs = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens
        }
        if system_prompt:
            kwargs["system"] = system_prompt

        try:
            response = self.client.messages.create(**kwargs)
            content = response.content[0].text
            if json_schema:
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse JSON from Anthropic response")
                    return {"content": content}
            return {"content": content}
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            raise


class OllamaProvider(LLMProvider):
    def __init__(self, llm_config: LLMConfig):
        self.config = llm_config
        self.base_url = llm_config.base_url or "http://localhost:11434"

    def generate(self, prompt: str, system_prompt: Optional[str] = None, json_schema: Optional[Dict[str, Any]] = None, quiet: bool = False) -> Dict[str, Any]:
        from lib.core import http

        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens
            }
        }
        if system_prompt:
            payload["system"] = system_prompt
        if json_schema:
            payload["format"] = "json"

        try:
            response = http.post(f"{self.base_url}/api/generate", json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            content = data.get("response", "")
            if json_schema:
                return json.loads(content)
            return {"content": content}
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            raise


class CerebrasProvider(LLMProvider):
    def __init__(self, llm_config: LLMConfig):
        self.config = llm_config
        try:
            import openai
            self.client = openai.OpenAI(
                api_key=llm_config.api_key,
                base_url=llm_config.base_url or "https://api.cerebras.ai/v1"
            )
        except ImportError:
            raise ImportError("openai package not installed. Install with: pip install openai")
        
        # Set up model list and rate limiters
        self.model_list = self._get_model_list(llm_config.model)
        self.rate_limiters = {
            model["name"]: RateLimiter(rpm=model["rpm"]) for model in CEREBRAS_MODELS
        }

    def _get_model_list(self, primary_model: str) -> List[str]:
        """Get ordered list of models to try (primary first, then fallbacks)"""
        model_names = [m["name"] for m in CEREBRAS_MODELS]
        # Start with primary model if it's in the list, otherwise start from first
        if primary_model in model_names:
            idx = model_names.index(primary_model)
            return model_names[idx:] + model_names[:idx]
        return model_names

    def generate(self, prompt: str, system_prompt: Optional[str] = None, json_schema: Optional[Dict[str, Any]] = None, quiet: bool = False) -> Dict[str, Any]:
        import sys
        logger.info("Starting AI request via Cerebras provider")
        if not quiet:
            print_status("Starting AI processing...", "info")
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        last_exception = None

        for model_name in self.model_list:
            try:
                logger.debug(f"Trying model: {model_name}")
                
                # Acquire rate limit token
                if model_name in self.rate_limiters:
                    logger.debug(f"Acquiring rate limit for model: {model_name}")
                    self.rate_limiters[model_name].acquire()
                
                kwargs = {
                    "model": model_name,
                    "messages": messages,
                    "temperature": self.config.temperature,
                    "max_tokens": self.config.max_tokens
                }

                if json_schema:
                    kwargs["response_format"] = {"type": "json_object"}

                response = self.client.chat.completions.create(**kwargs)
                content = response.choices[0].message.content
                
                if not quiet:
                    print_status("AI processing complete!", "success")
                logger.info(f"Success with Cerebras model: {model_name}")
                
                if json_schema:
                    return json.loads(content)
                return {"content": content, "model_used": model_name}
            except Exception as e:
                logger.warning(f"Model {model_name} failed: {e}")
                last_exception = e
                continue
        
        logger.error(f"All Cerebras models failed! Last error: {last_exception}")
        if not quiet:
            print_status("All AI models failed!", "error")
        raise last_exception or Exception("All models failed")


class GroqProvider(LLMProvider):
    def __init__(self, llm_config: LLMConfig):
        self.config = llm_config
        try:
            import openai
            self.client = openai.OpenAI(
                api_key=llm_config.api_key,
                base_url=llm_config.base_url or "https://api.groq.com/openai/v1"
            )
        except ImportError:
            raise ImportError("openai package not installed. Install with: pip install openai")
        
        # Set up model list and rate limiters
        self.model_list = self._get_model_list(llm_config.model)
        self.rate_limiters = {
            model["name"]: RateLimiter(rpm=model["rpm"]) for model in GROQ_MODELS
        }

    def _get_model_list(self, primary_model: str) -> List[str]:
        """Get ordered list of models to try (primary first, then fallbacks)"""
        model_names = [m["name"] for m in GROQ_MODELS]
        # Start with primary model if it's in the list, otherwise start from first
        if primary_model in model_names:
            idx = model_names.index(primary_model)
            return model_names[idx:] + model_names[:idx]
        return model_names

    def generate(self, prompt: str, system_prompt: Optional[str] = None, json_schema: Optional[Dict[str, Any]] = None, quiet: bool = False) -> Dict[str, Any]:
        import sys
        logger.info("Starting AI request via Groq provider")
        if not quiet:
            print_status("Starting AI processing...", "info")
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        last_exception = None

        for model_name in self.model_list:
            try:
                logger.debug(f"Trying model: {model_name}")
                
                # Acquire rate limit token
                if model_name in self.rate_limiters:
                    logger.debug(f"Acquiring rate limit for model: {model_name}")
                    self.rate_limiters[model_name].acquire()
                
                kwargs = {
                    "model": model_name,
                    "messages": messages,
                    "temperature": self.config.temperature,
                    "max_tokens": self.config.max_tokens
                }

                if json_schema:
                    kwargs["response_format"] = {"type": "json_object"}

                response = self.client.chat.completions.create(**kwargs)
                content = response.choices[0].message.content
                
                if not quiet:
                    print_status("AI processing complete!", "success")
                logger.info(f"Success with Groq model: {model_name}")
                
                if json_schema:
                    return json.loads(content)
                return {"content": content, "model_used": model_name}
            except Exception as e:
                logger.warning(f"Model {model_name} failed: {e}")
                last_exception = e
                continue
        
        logger.error(f"All Groq models failed! Last error: {last_exception}")
        if not quiet:
            print_status("All AI models failed!", "error")
        raise last_exception or Exception("All models failed")


class NvidiaProvider(LLMProvider):
    def __init__(self, llm_config: LLMConfig):
        self.config = llm_config
        try:
            import openai
            self.client = openai.OpenAI(
                api_key=llm_config.api_key,
                base_url=llm_config.base_url or "https://integrate.api.nvidia.com/v1"
            )
        except ImportError:
            raise ImportError("openai package not installed. Install with: pip install openai")
        
        # NVIDIA API has 40 RPM limit
        self.rate_limiter = RateLimiter(rpm=40)

    def generate(self, prompt: str, system_prompt: Optional[str] = None, json_schema: Optional[Dict[str, Any]] = None, quiet: bool = False) -> Dict[str, Any]:
        logger.info("Starting AI request via NVIDIA provider")
        if not quiet:
            print_status("Starting AI processing...", "info")
        
        # Acquire rate limit token
        self.rate_limiter.acquire()
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        kwargs = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens
        }

        if json_schema:
            kwargs["response_format"] = {"type": "json_object"}

        try:
            response = self.client.chat.completions.create(**kwargs)
            content = response.choices[0].message.content
            
            if not quiet:
                print_status("AI processing complete!", "success")
            logger.info(f"Success with NVIDIA model: {self.config.model}")
            
            if json_schema:
                return json.loads(content)
            return {"content": content, "model_used": self.config.model}
        except Exception as e:
            logger.error(f"NVIDIA API error: {e}")
            if not quiet:
                print_status("NVIDIA AI model failed!", "error")
            raise




def get_llm_config() -> LLMConfig:
    secrets_data = _load_llm_secrets()
    provider = os.environ.get("WAYMAP_LLM_PROVIDER") or secrets_data.get("provider", "none")
    api_key = os.environ.get("WAYMAP_LLM_API_KEY") or secrets_data.get("api_key")
    model = os.environ.get("WAYMAP_LLM_MODEL") or secrets_data.get("model", "gpt-oss-120b")
    temperature = float(os.environ.get("WAYMAP_LLM_TEMPERATURE") or secrets_data.get("temperature", "0.2"))
    max_tokens = int(os.environ.get("WAYMAP_LLM_MAX_TOKENS") or secrets_data.get("max_tokens", "1000"))
    base_url = os.environ.get("WAYMAP_LLM_BASE_URL") or secrets_data.get("base_url")

    return LLMConfig(
        provider=provider, api_key=api_key, model=model, temperature=temperature, max_tokens=max_tokens, base_url=base_url)


def _load_llm_secrets() -> Dict[str, Any]:
    from lib.core.secrets import _load_secrets_file
    secrets = _load_secrets_file()
    return secrets.get("llm", {})


def get_llm_provider() -> LLMProvider:
    llm_config = get_llm_config()

    if llm_config.provider == "none":
        return NoneProvider()
    elif llm_config.provider == "openai":
        return OpenAIProvider(llm_config)
    elif llm_config.provider == "anthropic":
        return AnthropicProvider(llm_config)
    elif llm_config.provider == "ollama":
        return OllamaProvider(llm_config)
    elif llm_config.provider == "cerebras":
        return CerebrasProvider(llm_config)
    elif llm_config.provider == "groq":
        return GroqProvider(llm_config)
    elif llm_config.provider == "nvidia":
        return NvidiaProvider(llm_config)
    else:
        logger.warning(f"Unknown LLM provider: {llm_config.provider}, using none")
        return NoneProvider()


def is_llm_available() -> bool:
    llm_config = get_llm_config()
    return llm_config.provider != "none" and llm_config.api_key


def save_llm_config_to_secrets(llm_config: LLMConfig) -> None:
    """Save LLM config to secrets.json"""
    from lib.core.secrets import _load_secrets_file
    import json
    import os
    data = _load_secrets_file()
    data["llm"] = {
        "provider": llm_config.provider,
        "api_key": llm_config.api_key,
        "model": llm_config.model,
        "temperature": llm_config.temperature,
        "max_tokens": llm_config.max_tokens,
        "base_url": llm_config.base_url
    }
    secrets_path = os.path.join(config.CONFIG_DIR, "secrets.json")
    try:
        with open(secrets_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved LLM config to {secrets_path}")
    except Exception as e:
        logger.error(f"Failed to save LLM config: {e}")
        raise


def test_llm_connection() -> bool:
    """Test if current LLM config is valid and reachable"""
    try:
        provider = get_llm_provider()
        if isinstance(provider, NoneProvider):
            return False
        # Try a simple prompt to test connection
        test_prompt = "Hello, please respond with only the word 'ok'."
        # Note: For Anthropic and other providers, we might need to adjust, but let's try generate
        try:
            result = provider.generate(test_prompt, "You are a helpful AI.", quiet=True)
            return bool(result)
        except Exception:
            return False
    except Exception:
        return False
