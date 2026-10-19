# -*- coding:UTF-8 -*-
"""
Ollama & IBM Granite 4.2 Uncensored (eriktonon/granite4.2-uncensored) Engine for SPO v2.0.
Integrates Erik Tonon's abliterated + SecOps LoRA fine-tuned model:
  https://ollama.com/eriktonon/granite4.2-uncensored
  - Base Architecture: IBM Granite 4.2 8B (40 layers, 128K context window)
  - Orthogonal Refusal Direction Abliteration (layers 10 to 35)
  - SecOps / DeepEvil LoRA for OSINT correlation, exploit analysis, threat modeling & AppSec
  - Recommended inference parameters: temperature=0.2, top_p=0.92, num_ctx=8192
"""
import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests


class OllamaGraniteEngine:
    DEFAULT_MODEL = "eriktonon/granite4.2-uncensored"
    DEFAULT_HOST = "http://localhost:11434"
    MODEL_HUB_URL = "https://ollama.com/eriktonon/granite4.2-uncensored"

    DEFAULT_OPTIONS = {
        "temperature": 0.2,
        "top_p": 0.92,
        "num_ctx": 8192,
    }

    SYSTEM_PROMPTS = {
        "osint_correlation": (
            "You are Granite 4.2 Uncensored (eriktonon/granite4.2-uncensored), an advanced OSINT, "
            "Threat Intelligence, and Red/Blue Team analysis engine integrated into SPO (Sneak Peek OSINT v2.0). "
            "Correlate all provided reconnaissance data (domains, RDAP/WHOIS, CNPJ/QSA corporate structure, "
            "subdomains, open ports, CVEs, GitHub commit emails, and social footprints). "
            "Produce a direct, technical, zero-fluff intelligence report structured into: "
            "1) Executive Threat & Exposure Summary, 2) High-Value Attack Surface & Pivot Vectors, "
            "3) Identity & Corporate Attribution Links, 4) Recommended Next Reconnaissance & Verification Steps."
        ),
        "redteam_surface": (
            "You are Granite 4.2 Uncensored (eriktonon/granite4.2-uncensored), a senior offensive security "
            "and penetration testing researcher. Analyze the target surface and provide technical enumeration "
            "hypotheses, advanced Google/GitHub/Shodan dorks, potential misconfiguration vectors (OWASP Top 10 / CWE), "
            "and concrete reproducible verification commands (curl, nmap, nuclei, ffuf, dig)."
        ),
        "vuln_exploit_analysis": (
            "You are Granite 4.2 Uncensored (eriktonon/granite4.2-uncensored), fine-tuned with SecOps LoRA for "
            "vulnerability research, CVE triage, reverse engineering, and Shift-Left remediation. "
            "Explain the root cause, exploitation mechanics, realistic impact, PoC verification pattern, "
            "and production-grade defensive code fix."
        ),
        "due_diligence": (
            "You are Granite 4.2 Uncensored (eriktonon/granite4.2-uncensored), assisting corporate compliance, "
            "legal due diligence, and M&A risk analysts. Evaluate corporate registration data (CNPJ/QSA), "
            "official gazette mentions, judicial exposure, and digital infrastructure governance risks."
        ),
    }

    def __init__(
        self,
        base_host: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout: int = 45,
    ):
        self.base_host = self.sanitize_host(
            base_host or os.environ.get("SPO_OLLAMA_HOST") or self.DEFAULT_HOST
        )
        self.model_name = (
            model_name or os.environ.get("SPO_OLLAMA_MODEL") or self.DEFAULT_MODEL
        ).strip()
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "SPO-Granite-Engine/2.0 (+https://eriktonon.com)",
            }
        )

    @classmethod
    def sanitize_host(cls, raw_host: str) -> str:
        cleaned = (raw_host or cls.DEFAULT_HOST).strip().rstrip("/")
        if not cleaned.startswith(("http://", "https://")):
            cleaned = f"http://{cleaned}"
        parsed = urlparse(cleaned)
        # Never allow targeting the protected OPNsense gateway 192.168.3.1
        if (parsed.hostname or "").strip() == "192.168.3.1":
            return cls.DEFAULT_HOST
        if parsed.scheme not in ("http", "https"):
            return cls.DEFAULT_HOST
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def _wsl_http_get(url: str, timeout_sec: int = 5) -> Optional[Dict[str, Any]]:
        if os.name != "nt":
            return None
        try:
            proc = subprocess.run(
                ["wsl", "curl", "-s", "-m", str(timeout_sec), url],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec + 3,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return json.loads(proc.stdout)
        except Exception:
            return None
        return None

    @staticmethod
    def _wsl_http_post(
        url: str, payload: Dict[str, Any], timeout_sec: int = 90
    ) -> Optional[Dict[str, Any]]:
        if os.name != "nt":
            return None
        try:
            proc = subprocess.run(
                [
                    "wsl",
                    "curl",
                    "-s",
                    "-m",
                    str(timeout_sec),
                    "-X",
                    "POST",
                    "-H",
                    "Content-Type: application/json",
                    "--data-binary",
                    "@-",
                    url,
                ],
                input=json.dumps(payload, ensure_ascii=False),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec + 5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return json.loads(proc.stdout)
        except Exception:
            return None
        return None

    def check_status(
        self,
        override_host: Optional[str] = None,
        override_model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Check Ollama server status and whether eriktonon/granite4.2-uncensored is available."""
        host = self.sanitize_host(override_host or self.base_host)
        target_model = (override_model or self.model_name or self.DEFAULT_MODEL).strip()
        tags_endpoint = f"{host}/api/tags"

        status_info: Dict[str, Any] = {
            "online": False,
            "host": host,
            "configured_model": target_model,
            "model_installed": False,
            "available_models": [],
            "model_hub_url": self.MODEL_HUB_URL,
            "pull_cmd": f"ollama pull {self.DEFAULT_MODEL}",
            "run_cmd": f"ollama run {self.DEFAULT_MODEL}",
            "parameters": self.DEFAULT_OPTIONS,
            "error": None,
        }

        data: Optional[Dict[str, Any]] = None
        try:
            resp = self.session.get(tags_endpoint, timeout=3)
            if resp.status_code == 200:
                data = resp.json()
        except Exception as exc:
            status_info["error"] = str(exc)

        if data is None:
            wsl_data = self._wsl_http_get("http://127.0.0.1:11434/api/tags", timeout_sec=4)
            if isinstance(wsl_data, dict) and "models" in wsl_data:
                data = wsl_data
                status_info["host"] = f"{host} (WSL2 Bridge)"
                status_info["error"] = None

        if isinstance(data, dict):
            models_list = [
                m.get("name", "")
                for m in data.get("models", [])
                if isinstance(m, dict) and m.get("name")
            ]
            status_info["online"] = True
            status_info["available_models"] = models_list
            base_target = target_model.split(":")[0].lower()
            status_info["model_installed"] = any(
                base_target in m.lower() for m in models_list
            )

        return status_info

    def _build_offline_fallback_analysis(
        self,
        prompt: str,
        mode: str,
        context_summary: Optional[str],
        host: str,
        model: str,
        error_detail: str,
    ) -> str:
        lines = [
            f"[MODO OFFLINE / HEURÍSTICO — Daemon Ollama indisponível em {host}]",
            f"Modelo Configurado: {model} (IBM Granite 4.2 8B Abliterated + SecOps LoRA)",
            f"Motivo da Conexão: {error_detail}",
            "",
            "=== SÍNTESE TÁTICA PRELIMINAR (FALLBACK DETERMINÍSTICO SPO) ===",
            f"• Modo Operacional Selecionado: {mode}",
            f"• Prompt / Escopo Solicitado: {prompt[:300]}",
        ]
        if context_summary:
            lines.extend(
                [
                    "• Evidência OSINT / DAST Correlacionada:",
                    f"  {context_summary[:600]}",
                ]
            )
        lines.extend(
            [
                "",
                "=== COMO ATIVAR O MOTOR NEURAL GRANITE 4.2 UNCENSORED ===",
                "1. Certifique-se de que o serviço Ollama está em execução (`ollama serve`).",
                f"2. Baixe a imagem oficial de Erik Tonon: `ollama pull {self.DEFAULT_MODEL}`",
                f"3. Ou execute diretamente: `ollama run {self.DEFAULT_MODEL}`",
                f"4. Hub Oficial: {self.MODEL_HUB_URL}",
            ]
        )
        return "\n".join(lines)

    def analyze(
        self,
        prompt: str,
        mode: str = "osint_correlation",
        context_payload: Optional[Any] = None,
        override_host: Optional[str] = None,
        override_model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute an OSINT / SecOps / Threat Intelligence analysis using
        eriktonon/granite4.2-uncensored via the Ollama /api/chat endpoint.
        """
        host = self.sanitize_host(override_host or self.base_host)
        model = (override_model or self.model_name or self.DEFAULT_MODEL).strip()
        system_prompt = self.SYSTEM_PROMPTS.get(mode, self.SYSTEM_PROMPTS["osint_correlation"])

        clean_prompt = (prompt or "").strip() or "Analyze the attached OSINT evidence and highlight the top security risks and pivot vectors."
        context_str = ""
        if context_payload:
            if isinstance(context_payload, str):
                context_str = context_payload[:12000]
            else:
                context_str = json.dumps(context_payload, ensure_ascii=False, indent=2, default=str)[:12000]

        user_message = clean_prompt
        if context_str:
            user_message = (
                f"{clean_prompt}\n\n"
                f"--- ATTACHED OSINT / STRIX EVIDENCE JSON ---\n"
                f"{context_str}"
            )

        chat_endpoint = f"{host}/api/chat"
        request_body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "options": self.DEFAULT_OPTIONS,
            "stream": False,
        }

        started = datetime.now(timezone.utc)
        err_msg = ""
        try:
            resp = self.session.post(chat_endpoint, json=request_body, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                content = (
                    data.get("message", {}).get("content")
                    or data.get("response")
                    or ""
                ).strip()
                elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
                return {
                    "ok": True,
                    "live_ollama": True,
                    "model": model,
                    "host": host,
                    "mode": mode,
                    "response": content,
                    "elapsed_ms": elapsed_ms,
                    "timestamp": started.strftime("%Y-%m-%d %H:%M:%S UTC"),
                }
            err_msg = f"HTTP {resp.status_code}: {resp.text[:240]}"
        except Exception as exc:
            err_msg = str(exc)

        # Fallback to WSL2 Ollama bridge if running on Windows and direct socket was refused
        wsl_resp = self._wsl_http_post(
            "http://127.0.0.1:11434/api/chat",
            payload=request_body,
            timeout_sec=max(self.timeout, 90),
        )
        if isinstance(wsl_resp, dict):
            content = (
                wsl_resp.get("message", {}).get("content")
                or wsl_resp.get("response")
                or ""
            ).strip()
            if content:
                elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
                return {
                    "ok": True,
                    "live_ollama": True,
                    "model": model,
                    "host": f"{host} (WSL2 Bridge)",
                    "mode": mode,
                    "response": content,
                    "elapsed_ms": elapsed_ms,
                    "timestamp": started.strftime("%Y-%m-%d %H:%M:%S UTC"),
                }

        fallback_text = self._build_offline_fallback_analysis(
            prompt=clean_prompt,
            mode=mode,
            context_summary=context_str[:600] if context_str else None,
            host=host,
            model=model,
            error_detail=err_msg,
        )
        return {
            "ok": False,
            "live_ollama": False,
            "model": model,
            "host": host,
            "mode": mode,
            "error": err_msg,
            "response": fallback_text,
            "elapsed_ms": 0,
            "timestamp": started.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

    @classmethod
    def get_model_metadata(cls) -> Dict[str, Any]:
        """Return technical metadata for eriktonon/granite4.2-uncensored."""
        return {
            "name": cls.DEFAULT_MODEL,
            "title": "IBM Granite 4.2 8B Uncensored (Abliterated + SecOps LoRA)",
            "author": "Erik Tonon (@eriktonon)",
            "hub_url": cls.MODEL_HUB_URL,
            "base_architecture": "IBM Granite 4.2 8B (GraniteForCausalLM, 40 layers)",
            "context_window": "128,000 tokens (num_ctx default: 8192)",
            "size": "5.7 GB",
            "abliteration": "Orthogonal Refusal Direction Abliteration across layers 10–35",
            "fine_tuning": "SecOps / DeepEvil LoRA (OSINT, Reverse Engineering, Exploit PoCs, Threat Modeling)",
            "parameters": cls.DEFAULT_OPTIONS,
        }
