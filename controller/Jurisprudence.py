# -*- coding:UTF-8 -*-
"""
Legal, Gazette & Jurisprudence OSINT Controller for SPO v2.0.
Combines live queries to Querido Diário API (Open Knowledge Brasil official gazettes)
with structured Legal & Compliance OSINT search vectors across Jusbrasil,
Diário Oficial da União (DOU), Portal da Transparência (CEIS/CNEP), Escavador, and CNJ.
"""
from typing import Dict
from urllib.parse import quote_plus
import requests


class Jurisprudence:
    HEADERS = {
        "User-Agent": "SPO-Sneak-Peek-OSINT/2.0 (+https://github.com/eriktonon/SPO-Sneak-Peek-OSINT)",
        "Accept": "application/json",
    }

    def jurisprudence(self, query_term: str) -> Dict[str, str]:
        """
        Search official gazettes via Querido Diário API and generate direct
        legal/compliance OSINT verification links for the given CNPJ or entity name.
        Returns a dictionary mapping descriptive labels to URLs.
        """
        if not query_term or not str(query_term).strip():
            return {}

        clean_term = str(query_term).strip()
        encoded = quote_plus(clean_term)
        digits_only = "".join(ch for ch in clean_term if ch.isdigit())

        results: Dict[str, str] = {}

        # 1. Live query to Querido Diário (Official Municipal Gazettes API)
        try:
            resp = requests.get(
                "https://queridodiario.ok.org.br/api/gazettes",
                params={"querystring": clean_term, "size": 5},
                headers=self.HEADERS,
                timeout=8,
            )
            if resp.status_code == 200:
                data = resp.json()
                for idx, gaz in enumerate(data.get("gazettes", [])[:5], start=1):
                    territory = gaz.get("territory_name") or "Município"
                    state = gaz.get("state_code") or ""
                    date = gaz.get("date") or "Data N/D"
                    url = gaz.get("url") or gaz.get("txt_url") or ""
                    if url:
                        label = f"Diário Oficial ({territory}/{state}) - {date} [#{idx}]"
                        results[label] = url
        except Exception:
            pass

        # 2. High-value Legal, Judicial & Compliance OSINT Portals
        results[f"Jusbrasil — Jurisprudência & Processos ({clean_term})"] = (
            f"https://www.jusbrasil.com.br/jurisprudencia/busca?q={encoded}"
        )
        results[f"Jusbrasil — Diários Oficiais ({clean_term})"] = (
            f"https://www.jusbrasil.com.br/diarios/busca?q={encoded}"
        )
        results[f"Diário Oficial da União (Imprensa Nacional DOU)"] = (
            f"https://www.in.gov.br/consulta/-/buscar/dou?q=%22{encoded}%22&s=todos&exactDate=all&sortType=0"
        )
        results[f"Escavador — Monitoramento de Processos e Partes"] = (
            f"https://www.escavador.com/busca?q={encoded}&qo=t"
        )
        if digits_only:
            results[f"Portal da Transparência — Sanções CEIS/CNEP/CEPIM ({digits_only})"] = (
                f"https://portaldatransparencia.gov.br/sancoes/consulta?cpfCnpj={digits_only}"
            )
            results[f"PNCP — Contratos e Atas no Portal Nacional de Contratações"] = (
                f"https://pncp.gov.br/app/contratos?q={digits_only}"
            )
        results[f"Google Legal Dork (Intimações, Editais & PDFs Judiciais)"] = (
            f"https://www.google.com/search?q=%22{encoded}%22+(site:jus.br+OR+site:jusbrasil.com.br+OR+site:in.gov.br)"
        )

        return results
