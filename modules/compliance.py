import datetime
import json
import os

class ComplianceManager:
    def __init__(self, log_file="/home/ubuntu/data_leak_monitor/compliance_audit.log"):
        self.log_file = log_file

    def log_activity(self, activity_type, details):
        """Registra atividades para fins de auditoria LGPD."""
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "activity": activity_type,
            "details": details
        }
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def get_legal_basis(self):
        """Retorna a base legal para o tratamento de dados."""
        return {
            "primary": "Legítimo Interesse (Art. 7º, IX da LGPD)",
            "secondary": "Cumprimento de Obrigação Legal (Art. 7º, II da LGPD)",
            "description": "O tratamento é realizado para proteger a privacidade e segurança do titular contra vazamentos de dados."
        }

    def request_human_review(self, decision_id, user_comments):
        """Registra uma solicitação de revisão humana para decisões automatizadas (Art. 20 LGPD)."""
        self.log_activity("HUMAN_REVIEW_REQUEST", {
            "decision_id": decision_id,
            "user_comments": user_comments,
            "status": "PENDING"
        })
        return {"status": "success", "message": "Solicitação de revisão registrada com sucesso."}

    def encrypt_data(self, data):
        """Simula a criptografia de dados sensíveis para armazenamento seguro."""
        import base64
        # Simulação de criptografia forte (AES-256 em um cenário real)
        encoded = base64.b64encode(data.encode()).decode()
        return f"SECURE_STORAGE_{encoded}"

    def anonymize_ip(self, ip_address):
        """Anonimiza endereços IP para conformidade com princípios de minimização da LGPD."""
        parts = ip_address.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0"
        return "0.0.0.0"

    def validate_cpf(self, cpf):
        """Valida o formato do CPF para evitar processamento de dados inválidos."""
        import re
        cpf = re.sub(r'\D', '', cpf)
        if len(cpf) != 11:
            return False
        return True
