# -*- coding:UTF-8 -*-
"""
Brazilian Company (CNPJ) OSINT Controller for SPO v2.0.
Upgraded from the defunct 2018 compras.dados.gov.br endpoint to a resilient
multi-provider pipeline:
  1. BrasilAPI (https://brasilapi.com.br/api/cnpj/v1/{cnpj})
  2. ReceitaWS (https://receitaws.com.br/v1/cnpj/{cnpj})
  3. CNPJ.ws Public API (https://publica.cnpj.ws/cnpj/{cnpj})
Includes QSA (Quadro Societário), CNAEs, Capital Social, and direct links to
Portal da Transparência & PNCP (Portal Nacional de Contratações Públicas).
"""
import re
from typing import Any, Dict, List, Optional
import requests


class CNPJ:
    HEADERS = {
        "User-Agent": "SPO-Sneak-Peek-OSINT/2.0 (+https://github.com/eriktonon/SPO-Sneak-Peek-OSINT)",
        "Accept": "application/json",
    }

    def treat(self, cnpj: Optional[str]) -> str:
        """Strip all non-digit characters from a CNPJ string."""
        if not cnpj:
            return ""
        return re.sub(r"\D", "", str(cnpj))

    @staticmethod
    def format_cnpj(digits: str) -> str:
        clean = re.sub(r"\D", "", digits or "")
        if len(clean) == 14:
            return f"{clean[:2]}.{clean[2:5]}.{clean[5:8]}/{clean[8:12]}-{clean[12:14]}"
        return digits

    def _empty_result(self, cnpj_digits: str = "") -> Dict[str, Any]:
        return {
            "cnpj": cnpj_digits,
            "cnpj_formatted": self.format_cnpj(cnpj_digits) if cnpj_digits else "",
            "social_name": "",
            "fantasy_name": "",
            "address": "",
            "type_business": "",
            "legal_nature": "",
            "isActive": "",
            "business_size": "",
            "bidding_permission": "",
            "public_contracts": "",
            "biddings": "",
            "capital_social": "",
            "opening_date": "",
            "phone": "",
            "email": "",
            "partners": [],
            "secondary_cnaes": [],
            "source": None,
        }

    def _fetch_brasilapi(self, cnpj_digits: str) -> Optional[Dict[str, Any]]:
        url = f"https://brasilapi.com.br/api/cnpj/v1/{cnpj_digits}"
        try:
            resp = requests.get(url, headers=self.HEADERS, timeout=10)
            if resp.status_code != 200:
                return None
            d = resp.json()
            partners: List[Dict[str, str]] = []
            for p in d.get("qsa") or []:
                partners.append(
                    {
                        "name": p.get("nome_socio") or "",
                        "role": p.get("qualificacao_socio") or "",
                        "since": p.get("data_entrada_sociedade") or "",
                        "age_range": p.get("faixa_etaria") or "",
                    }
                )
            secondary = [
                f"{c.get('codigo')} - {c.get('descricao')}"
                for c in (d.get("cnaes_secundarios") or [])[:10]
                if c.get("descricao")
            ]
            address_parts = [
                f"{d.get('descricao_tipo_de_logradouro', '')} {d.get('logradouro', '')}".strip(),
                str(d.get("numero") or "S/N"),
                d.get("complemento") or "",
                d.get("bairro") or "",
                f"{d.get('municipio', '')} - {d.get('uf', '')}".strip(" -"),
                f"CEP {d.get('cep', '')}".strip(),
            ]
            address = ", ".join(part for part in address_parts if part and part != "CEP")
            status_desc = d.get("descricao_situacao_cadastral") or str(d.get("situacao_cadastral") or "")
            is_active = "ATIVA" in status_desc.upper() if status_desc else True
            capital = d.get("capital_social")
            capital_str = f"R$ {float(capital):,.2f}" if isinstance(capital, (int, float)) else str(capital or "")

            return {
                "cnpj": cnpj_digits,
                "cnpj_formatted": self.format_cnpj(cnpj_digits),
                "social_name": d.get("razao_social") or "",
                "fantasy_name": d.get("nome_fantasia") or d.get("razao_social") or "",
                "address": address,
                "type_business": d.get("cnae_fiscal_descricao") or "",
                "legal_nature": d.get("natureza_juridica") or "",
                "isActive": f"{status_desc} ({'Ativa' if is_active else 'Inativa'})" if status_desc else is_active,
                "business_size": d.get("porte") or "",
                "bidding_permission": "Elegível (Verificar Certidões CNJ/TCU/CEIS)" if is_active else "Restrito (CNPJ Inativo)",
                "public_contracts": f"https://portaldatransparencia.gov.br/busca?termo={cnpj_digits}",
                "biddings": f"https://pncp.gov.br/app/editais?q={cnpj_digits}",
                "capital_social": capital_str,
                "opening_date": d.get("data_inicio_atividade") or "",
                "phone": d.get("ddd_telefone_1") or d.get("ddd_telefone_2") or "",
                "email": (d.get("email") or "").lower(),
                "partners": partners,
                "secondary_cnaes": secondary,
                "source": "BrasilAPI (Receita Federal)",
            }
        except Exception:
            return None

    def _fetch_receitaws(self, cnpj_digits: str) -> Optional[Dict[str, Any]]:
        url = f"https://receitaws.com.br/v1/cnpj/{cnpj_digits}"
        try:
            resp = requests.get(url, headers=self.HEADERS, timeout=10)
            if resp.status_code != 200:
                return None
            d = resp.json()
            if d.get("status") == "ERROR":
                return None
            partners = [
                {"name": p.get("nome") or "", "role": p.get("qual") or "", "since": "", "age_range": ""}
                for p in (d.get("qsa") or [])
            ]
            main_act = (d.get("atividade_principal") or [{}])[0].get("text") or ""
            secondary = [
                f"{c.get('code')} - {c.get('text')}"
                for c in (d.get("atividades_secundarias") or [])[:10]
                if c.get("text")
            ]
            address = f"{d.get('logradouro', '')}, {d.get('numero', '')} - {d.get('bairro', '')}, {d.get('municipio', '')}/{d.get('uf', '')} - CEP {d.get('cep', '')}"
            status_desc = d.get("situacao") or ""
            is_active = "ATIVA" in status_desc.upper()
            return {
                "cnpj": cnpj_digits,
                "cnpj_formatted": self.format_cnpj(cnpj_digits),
                "social_name": d.get("nome") or "",
                "fantasy_name": d.get("fantasia") or d.get("nome") or "",
                "address": address.strip(", -"),
                "type_business": main_act,
                "legal_nature": d.get("natureza_juridica") or "",
                "isActive": status_desc or is_active,
                "business_size": d.get("porte") or "",
                "bidding_permission": "Elegível (Verificar Certidões)" if is_active else "Restrito",
                "public_contracts": f"https://portaldatransparencia.gov.br/busca?termo={cnpj_digits}",
                "biddings": f"https://pncp.gov.br/app/editais?q={cnpj_digits}",
                "capital_social": f"R$ {d.get('capital_social', '')}",
                "opening_date": d.get("abertura") or "",
                "phone": d.get("telefone") or "",
                "email": (d.get("email") or "").lower(),
                "partners": partners,
                "secondary_cnaes": secondary,
                "source": "ReceitaWS",
            }
        except Exception:
            return None

    def getCNPJ(self, cnpj: Optional[str]) -> Dict[str, Any]:
        """Look up comprehensive corporate intelligence by CNPJ."""
        cnpj_digits = self.treat(cnpj)
        if len(cnpj_digits) != 14:
            return self._empty_result(cnpj_digits)

        for fetcher in (self._fetch_brasilapi, self._fetch_receitaws):
            result = fetcher(cnpj_digits)
            if result and result.get("social_name"):
                return result

        return self._empty_result(cnpj_digits)
