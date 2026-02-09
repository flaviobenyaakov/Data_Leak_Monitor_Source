import json
from openai import OpenAI

class AIAnalyzer:
    def __init__(self):
        # O Manus já tem o cliente OpenAI pré-configurado
        self.client = OpenAI()

    def analyze_risk(self, scan_results):
        """Usa IA para analisar os resultados da varredura e priorizar riscos."""
        prompt = f"""
        Analise os seguintes resultados de varredura de vazamento de dados e forneça uma avaliação de risco.
        Considere a sensibilidade dos dados expostos e a fonte.
        
        Resultados da Varredura:
        {json.dumps(scan_results, indent=2)}
        
        Responda em formato JSON com os seguintes campos:
        - risk_level: (Baixo, Médio, Alto, Crítico)
        - risk_score: (0 a 100)
        - summary: Resumo claro do que foi encontrado.
        - sensitive_data_exposed: Lista de tipos de dados sensíveis identificados.
        - recommendations: Lista de ações recomendadas para o usuário.
        - lgpd_impact: Breve análise do impacto sob a ótica da LGPD.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4.1-mini",
                messages=[
                    {"role": "system", "content": "Você é um especialista em cibersegurança e privacidade de dados (LGPD)."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            
            analysis = json.loads(response.choices[0].message.content)
            return analysis
        except Exception as e:
            return {
                "risk_level": "Erro",
                "summary": f"Falha na análise por IA: {str(e)}",
                "recommendations": ["Verificar manualmente os resultados da varredura."]
            }
