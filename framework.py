import json
import os
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_google_genai import ChatGoogleGenerativeAI

def executar_virtual_patching_escalavel():
    print("\n🤖 [FASE 1] Iniciando Framework de Virtual Patching Agnóstico e Escalável...")

    report_path = 'reports/report.json'

    if not os.path.exists(report_path):
        print("❌ Erro: Relatório 'reports/report.json' não encontrado.")
        return

    with open(report_path, 'r', encoding='utf-8') as f:
        trivy_data = json.load(f)

    vulnerabilities = []
    ecossistema = "Desconhecido"
    arquivo_alvo_sugerido = "patch_seguranca"

    # Identifica dinamicamente o ecossistema com base no relatório do Trivy
    for result in trivy_data.get('Results', []):
        target_type = result.get('Type', '').lower()
        if 'Vulnerabilities' in result:
            vulnerabilities.extend(result['Vulnerabilities'])
            
        if 'composer' in target_type:
            ecossistema = "PHP (Composer)"
            arquivo_alvo_sugerido = "virtual_patch_bootstrap.php"
        elif 'npm' in target_type or 'yarn' in target_type:
            ecossistema = "Node.js (NPM)"
            arquivo_alvo_sugerido = "virtual_patch_middleware.js"
        elif 'pip' in target_type or 'poetry' in target_type:
            ecossistema = "Python (PIP)"
            arquivo_alvo_sugerido = "virtual_patch_interceptor.py"

    if not vulnerabilities:
        print("✅ Nenhuma vulnerabilidade detectada no repositório legado.")
        return

    print(f"📦 Ecossistema Detectado Automaticamente: {ecossistema}")
    print(f"🔍 Mapeadas {len(vulnerabilities)} vulnerabilidades para mitigação.")

    llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.1)

    prompt_template = PromptTemplate.from_template(
        """
        Você é um agente de IA sênior especialista em AppSec, DevSecOps e Arquitetura de Software.
        Sua missão é criar um arquivo de VIRTUAL PATCHING autônomo para mitigar as vulnerabilidades encontradas no ecossistema informado.

        [DIRETRIZES DE ARQUITETURA]
        1. Você deve gerar um arquivo isolado de proteção (um patch/interceptador/middleware) específico para o ecossistema: {ecossistema}.
        2. Esse arquivo deve conter regras de segurança (como sanitização de inputs, validação de cabeçalhos ou bloqueio de payloads maliciosos) projetadas especificamente para neutralizar as CVEs listadas.
        3. O objetivo é que este arquivo seja incluído no ponto de entrada do sistema legado para agir como um escudo, sem alterar as bibliotecas originais.
        4. FORMATO DE SAÍDA: Retorne APENAS o código puríssimo do arquivo protetivo, pronto para ser salvo. Não use marcações de markdown (como ```php ou ```javascript) e não escreva explicações textuais.

        [RELATÓRIO DE VULNERABILIDADES DO TRIVY]
        {vulns}
        """
    )

    chain = prompt_template | llm | StrOutputParser()

    print(f"🧠 [FASE 2] IA calculando e projetando o Virtual Patch para {ecossistema}...")
    codigo_patch = chain.invoke({
        "ecossistema": ecossistema,
        "vulns": json.dumps(vulnerabilities, indent=2)
    })

    # Sanitize para garantir que nenhuma tag de markdown quebre o arquivo gerado
    codigo_limpo = codigo_patch.replace("```php", "").replace("```javascript", "").replace("```python", "").replace("```", "").strip()

    # Salva o arquivo dinamicamente com o nome e extensão corretos da tecnologia detectada
    print(f"💾 [FASE 3] Gravando o escudo protetivo autônomo: {arquivo_alvo_sugerido}")
    with open(arquivo_alvo_sugerido, 'w', encoding='utf-8') as f:
        f.write(codigo_limpo)
        
    # Salva um arquivo de metadados para o pipeline do GitHub Actions saber o que foi gerado
    with open('patch_meta.json', 'w', encoding='utf-8') as f:
        json.dump({"arquivo_gerado": arquivo_alvo_sugerido, "ecossistema": ecossistema}, f)

    print(f"✅ [FASE 4] Virtual Patching concluído com sucesso para a tecnologia {ecossistema}!")

if __name__ == "__main__":
    executar_virtual_patching_escalavel()