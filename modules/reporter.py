import json
import datetime

class Reporter:
    def __init__(self):
        pass

    def generate_markdown_report(self, target, scan_results, ai_analysis):
        """Gera um relatório claro e objetivo em formato Markdown."""
        report = f"""# Relatório de Monitoramento de Vazamento de Dados
**Data do Relatório:** {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
**Alvo Monitorado:** {target}

## 1. Resumo da Avaliação de Risco
- **Nível de Risco:** {ai_analysis.get('risk_level', 'N/A')}
- **Pontuação de Risco:** {ai_analysis.get('risk_score', 'N/A')}/100
- **Impacto LGPD:** {ai_analysis.get('lgpd_impact', 'N/A')}

### Resumo Executivo
{ai_analysis.get('summary', 'Nenhum resumo disponível.')}

## 2. Detalhes das Exposições Identificadas
### Dados Sensíveis Expostos
{", ".join(ai_analysis.get('sensitive_data_exposed', ['Nenhum dado sensível identificado']))}

### Fontes de Vazamento
- **Have I Been Pwned:** {len(scan_results.get('hibp', [])) if isinstance(scan_results.get('hibp'), list) else 'N/A'} brechas encontradas.
- **IntelX:** {len(scan_results.get('intelx', []))} registros encontrados.
- **DeHashed:** {len(scan_results.get('dehashed', []))} entradas encontradas.

## 3. Recomendações de Segurança
"""
        for rec in ai_analysis.get('recommendations', []):
            report += f"- {rec}\n"
            
        report += """
---
*Este relatório foi gerado automaticamente pelo Sistema de Monitoramento de Vazamentos Manus AI em conformidade com a LGPD.*
"""
        return report

    def save_report(self, report_content, filename):
        with open(filename, "w") as f:
            f.write(report_content)
        return filename
