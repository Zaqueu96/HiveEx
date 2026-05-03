## HiveEx GUI - Graphical Interface

A GUI profissional para facilitar a extração de hives Windows de imagens forenses sem necessidade de usar o terminal.

### Instalação

1. **Instale as dependências:**
```bash
pip install -r requirements_new.txt
```

2. **PySimpleGUI será instalado automaticamente** com a dependência acima.

### Como usar

#### Modo GUI (Recomendado para não-técnicos)

```bash
# Iniciar a GUI
python hivex.py --gui
# ou
python hivex.py -g
```

#### Modo CLI (Tradicional)

```bash
# Sem argumento --gui, funciona como antes
python hivex.py --image image.E01 --sam
```

### Guia da Interface Gráfica

#### 1. **Seleção de Imagens**
- **📁 Browse Images**: Seleciona múltiplas imagens de uma só vez
- **➕ Add Image**: Adiciona uma imagem por vez
- **❌ Remove Image**: Remove a imagem selecionada da lista
- **🗑️ Clear All**: Remove todas as imagens

#### 2. **Opções de Extração**
Selecione um ou mais hives para extrair:
- **SAM**: Banco de dados de senhas do Windows
- **SYSTEM**: Arquivo de configuração do sistema
- **SOFTWARE**: Configurações de programas instalados
- **SECURITY**: Informações de segurança e auditoria
- **NTUSER.DAT**: Configurações do perfil do usuário
- **All Hives**: Extrai todos os hives acima
- **Specific File**: Extrai um arquivo específico com suporte a placeholder `[user]`

#### 3. **Arquivos de Configuração**
- Lista de configurações YAML disponíveis
- Pode selecionar múltiplas configurações
- As configurações definem quais hives extrair
- **🔄 Refresh Configs**: Recarrega as configurações disponíveis

#### 4. **Configuração de Saída**
- **Output Path**: Diretório onde os arquivos extraídos serão salvos (padrão: diretório atual)
- **Debug Mode**: Mostra erros detalhados no console
- **Verbose Logging**: Registra informações mais detalhadas

#### 5. **Execução**
- **▶️ Start Extraction**: Inicia o processo de extração
- **⏹️ Cancel**: Cancela a extração em andamento
- **❌ Exit**: Fecha a aplicação

#### 6. **Monitoramento**
- **Progress Bar**: Mostra o progresso da extração
- **Log Output**: Mostra mensagens de progresso e erros em tempo real

### Exemplos de Uso

#### Extrair SAM de uma imagem
1. Clique em **📁 Browse Images**
2. Selecione `image.E01`
3. Marque o checkbox **SAM**
4. Clique em **▶️ Start Extraction**

#### Extrair múltiplas imagens com configurações
1. Clique em **📁 Browse Images** e selecione `image1.E01` e `image2.E01`
2. Selecione as configurações desejadas em **Arquivos de Configuração**
3. Clique em **▶️ Start Extraction**

#### Extrair arquivo específico com placeholder
1. Adicione uma ou mais imagens
2. Marque **Specific File**
3. Digite o caminho com placeholder: `/Users/[user]/Downloads/important.txt`
4. Clique em **▶️ Start Extraction**

### Recursos Principais

✅ **Interface intuitiva**: Desenvolvida para peritos forenses não-técnicos
✅ **Múltiplas imagens**: Processa várias imagens em uma execução
✅ **Configurações YAML**: Use arquivos de configuração pré-definidos
✅ **Feedback em tempo real**: Veja o progresso ao vivo
✅ **Tratamento de erros**: Mensagens claras em caso de problemas
✅ **Logging detalhado**: Opção de saída verbose para diagnóstico

### Arquitetura

A GUI (`gui.py`) utiliza:
- **PySimpleGUI**: Interface gráfica multiplataforma
- **Threading**: Execução de extração sem travar a interface
- **HiveExCLI**: Reutiliza toda lógica de extração do CLI
- **Logger**: Sistema de logging integrado para debugging

### Troubleshooting

**Problema**: "PySimpleGUI is not installed"
**Solução**: Execute `pip install PySimpleGUI`

**Problema**: "No configurations loaded"
**Solução**: Clique em **🔄 Refresh Configs** ou verifique se os arquivos YAML estão em `hives_configs/`

**Problema**: "Error opening image"
**Solução**: Verifique se o caminho da imagem está correto e o arquivo é um E01 válido

### Comparação CLI vs GUI

| Feature | CLI | GUI |
|---------|-----|-----|
| Linhas de comando | ✅ | ❌ |
| Interface gráfica | ❌ | ✅ |
| Processamento em batch | ✅ | ✅ |
| Múltiplas imagens | ✅ | ✅ |
| Configurações YAML | ✅ | ✅ |
| Amigável para não-técnicos | ❌ | ✅ |
| Eficiência em scripts | ✅ | ❌ |

### Notas de Desenvolvedor

- A GUI reutiliza toda lógica de CLI através de `HiveExCLI`
- Threading é usado para manter a interface responsiva
- O log output atualiza em tempo real
- Suporta todas as opções de CLI através da interface gráfica

