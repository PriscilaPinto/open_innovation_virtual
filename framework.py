import json
import os
import subprocess
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_google_genai import ChatGoogleGenerativeAI

def executar_framework_autonomo():
    print("\n🤖 [FASE 1] Iniciando Framework de Remediação Autônoma...")

    report_path = 'reports/report.json'
    alvo_path = 'index.php'
    # O arquivo original fica 100% INTACTO. Geramos apenas o artefato de patch.
    patch_path = 'index_remediated.php' 

    if not os.path.exists(report_path):
        print("❌ Erro: Relatório 'reports/report.json' não encontrado.")
        return

    if not os.path.exists(alvo_path):
        print(f"❌ Erro: O arquivo alvo '{alvo_path}' não existe.")
        return

    # Lendo dados do Trivy e do código atual
    with open(report_path, 'r', encoding='utf-8') as f:
        trivy_data = json.load(f)

    vulnerabilities = []
    for result in trivy_data.get('Results', []):
        if 'Vulnerabilities' in result:
            vulnerabilities.extend(result['Vulnerabilities'])

    print(f"🔍 Mapeadas {len(vulnerabilities)} vulnerabilidades no ambiente legado.")

    with open(alvo_path, 'r', encoding='utf-8') as f:
        codigo_atual = f.read()

    # Chamando a inteligência do LangChain (Gemini 2.5 Flash)
    llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.1)

    prompt_template = PromptTemplate.from_template(
        """
        Você é um agente de IA autônomo especialista em AppSec e Cyber Threat Intelligence (CTI).
        Sua missão é aplicar a técnica de VIRTUAL PATCHING em uma aplicação PHP legada.

        [DIRETRIZES OBRIGATÓRIAS]
        1. É PROIBIDO atualizar as versões no composer.json ou alterar bibliotecas no composer.lock.
        2. Crie uma camada de segurança ou lógica de validação/interceptação estrita no início do código que neutralize os vetores de ataque dos CVEs informados.
        3. FORMATO DE SAÍDA: Retorne APENAS o código PHP completo, limpo e corrigido para substituir o arquivo atual. Não inclua blocos de código markdown (```php), nem explicações em texto.

        [CÓDIGO PHP ATUAL (index.php)]
        {code}

        [RELATÓRIO DE VULNERABILIDADES DO TRIVY]
        {vulns}

        Gere a solução de Virtual Patching agora:
        """
    )

    chain = prompt_template | llm | StrOutputParser()

    print("🧠 [FASE 2] IA analisando CVEs e gerando código protótipo...")
    codigo_remediado = chain.invoke({
        "code": codigo_atual,
        "vulns": json.dumps(vulnerabilities, indent=2)
    })

    # Gravando o patch proposto em um arquivo separado para auditoria da pipeline
    print(f"💾 Salvando proposta de Virtual Patching em '{patch_path}'...")
    with open(patch_path, 'w', encoding='utf-8') as f:
        f.write(codigo_remediado)

    # 3. FASE 3: Validação Prévia (Verificação de Integridade Básica)
    print(f"🧪 [FASE 3] Iniciando Teste Estático de Sintaxe em '{patch_path}'...")
    
    try:
        resultado = subprocess.run(['php', '-l', patch_path], capture_output=True, text=True, check=True)
        
        print("✅ Teste de Sintaxe Passou! O código gerado pela IA é perfeitamente válido.")
        print(f"🚀 [ARTEFATO PRONTO] O arquivo '{patch_path}' está qualificado para o próximo Job de Validação Dinâmica.")
        
    except subprocess.CalledProcessError as e:
        print("❌ CRÍTICO: A IA gerou um código quebrado!")
        print(f"Erro do compilador PHP: {e.stderr}")
        print("🛡️ Operação abortada no Job 1. O artefato falhou na validação inicial.")
        return
        
    except FileNotFoundError:
        print("⚠️ Nota: Interpretador 'php' não encontrado no ambiente local para o pré-teste.")
        print(f"O arquivo '{patch_path}' foi gerado e será validado diretamente na esteira de CI/CD.")

    print("📦 [FASE 4] Conclusão do Agente: Mudanças salvas isoladamente. Pronto para o próximo Job.")

if __name__ == "__main__":
    executar_framework_autonomo()