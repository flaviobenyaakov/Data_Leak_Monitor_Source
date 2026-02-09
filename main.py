import os
import sys
import json
from modules.scanner import DataLeakScanner
from modules.ai_analyzer import AIAnalyzer
from modules.compliance import ComplianceManager
from modules.reporter import Reporter

def main():
    # Configurações (Em produção, usar variáveis de ambiente ou cofre de senhas)
    HIBP_KEY = os.getenv("HIBP_API_KEY", "SIMULATED_KEY")
    INTELX_KEY = os.getenv("INTELX_API_KEY", "SIMULATED_KEY")
    DEHASHED_KEY = os.getenv("DEHASHED_API_KEY", "SIMULATED_KEY")
    DEHASHED_EMAIL = os.getenv("DEHASHED_EMAIL", "admin@example.com")

    # Inicializar módulos
    scanner = DataLeakScanner(HIBP_KEY, INTELX_KEY, DEHASHED_KEY, DEHASHED_EMAIL)
    analyzer = AIAnalyzer()
    compliance = ComplianceManager()
    reporter = Reporter()

    # Alvo para monitoramento (Exemplo)
    target = "usuario_exemplo@email.com"
    
    print(f"[*] Iniciando monitoramento para: {target}")
    compliance.log_activity("SCAN_START", {"target": target})

    # 1. Varredura (Simulada se as chaves forem inválidas)
    print("[*] Realizando varredura na Web e Darkweb...")
    scan_results = scanner.full_scan(target)
    
    # Simulação de dados para demonstração se as APIs falharem por falta de chaves reais
    if "error" in str(scan_results) or (not scan_results.get("hibp") and not scan_results.get("intelx") and not scan_results.get("dehashed")):
        print("[!] Usando dados simulados para demonstração (Chaves de API não configuradas)")
        scan_results = {
            "target": target,
            "hibp": [{"Name": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Email", "Passwords"]}],
            "intelx": [{"name": "ComboList_2024.txt", "date": "2024-01-15", "bucket": "darknet.tor"}],
            "dehashed": [{"email": target, "database": "Canva_Leak"}]
        }

    # 2. Análise por IA
    print("[*] Analisando riscos com Inteligência Artificial...")
    ai_analysis = analyzer.analyze_risk(scan_results)
    compliance.log_activity("AI_ANALYSIS_COMPLETE", {"target": target, "risk_level": ai_analysis.get("risk_level")})

    # 3. Geração de Relatório
    print("[*] Gerando relatório de conformidade...")
    report_md = reporter.generate_markdown_report(target, scan_results, ai_analysis)
    report_file = f"/home/ubuntu/data_leak_monitor/report_{target.replace('@', '_')}.md"
    reporter.save_report(report_md, report_file)
    
    print(f"[+] Monitoramento concluído. Relatório salvo em: {report_file}")
    compliance.log_activity("SCAN_FINISHED", {"target": target, "report_file": report_file})

if __name__ == "__main__":
    main()
