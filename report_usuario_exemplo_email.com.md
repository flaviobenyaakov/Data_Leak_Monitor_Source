# Relatório de Monitoramento de Vazamento de Dados
**Data do Relatório:** 04/02/2026 15:15:40
**Alvo Monitorado:** usuario_exemplo@email.com

## 1. Resumo da Avaliação de Risco
- **Nível de Risco:** Alto
- **Pontuação de Risco:** 85/100
- **Impacto LGPD:** O vazamento envolve dados pessoais sensíveis (e-mail e senhas), sujeitando o controlador ao risco de incidentes de segurança que podem afetar os titulares dos dados. Sob a LGPD, há obrigação de notificação ao titular e à Autoridade Nacional de Proteção de Dados (ANPD), além da adoção de medidas para mitigar danos e reforçar a segurança da informação.

### Resumo Executivo
O usuário teve seu e-mail e senhas expostos na violação da Adobe em 2013, esses dados também aparecem em uma lista combinada (ComboList_2024.txt) disponível na darknet, e seu e-mail foi identificado em vazamento relacionado à plataforma Canva. Isso indica que dados sensíveis de autenticação e dados pessoais estão amplamente expostos, elevando o risco de uso malicioso, como fraudes e ataques de engenharia social.

## 2. Detalhes das Exposições Identificadas
### Dados Sensíveis Expostos
E-mail, Senha

### Fontes de Vazamento
- **Have I Been Pwned:** 1 brechas encontradas.
- **IntelX:** 1 registros encontrados.
- **DeHashed:** 1 entradas encontradas.

## 3. Recomendações de Segurança
- Alterar imediatamente todas as senhas associadas ao e-mail vazado, especialmente na Adobe, Canva e serviços similares.
- Utilizar senhas únicas e complexas para cada serviço, preferencialmente com um gerenciador de senhas.
- Ativar autenticação de múltiplos fatores (MFA) sempre que possível.
- Monitorar regularmente contas para atividades suspeitas e revisar configurações de segurança.
- Verificar se dados pessoais adicionais foram comprometidos e, se necessário, monitorar possíveis usos indevidos, como fraude de identidade.

---
*Este relatório foi gerado automaticamente pelo Sistema de Monitoramento de Vazamentos em conformidade com a LGPD.*
