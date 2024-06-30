# Forensic Analysis Script

Este script Python é usado para analisar imagens forenses no formato E01, extraindo informações específicas dos arquivos NTUSER.DAT dos usuários no sistema Windows.

## Tecnologias Usadas

- **Python**: Linguagem de programação principal utilizada no script.
- **pyewf**: Biblioteca usada para ler e processar imagens EWF (Expert Witness Format).
- **pytsk3**: Biblioteca usada para interagir com o sistema de arquivos na imagem EWF.
- **utils.fileObjectUtils.FileObjectUtils**: Uma utilidade personalizada para manipulação de arquivos e cálculo de hashes.

## Propósito

O objetivo deste script é:

1. Abrir e ler uma imagem E01 segmentada.
2. Acessar a tabela de partições da imagem.
3. Verificar partições que contêm um sistema de arquivos NTFS.
4. Navegar pelo diretório `/Users/` e encontrar os arquivos NTUSER.DAT de cada usuário.
5. Calcular os hashes MD5, SHA-1 e SHA-256 para cada NTUSER.DAT encontrado.
6. Extrair o arquivo NTUSER.DAT para um diretório específico.

## Instruções

### Requisitos

Certifique-se de ter Python instalado e as seguintes bibliotecas:

- pyewf
- pytsk3
- utils (um módulo personalizado)

### Uso

1. Clone ou faça download deste repositório.
2. Edite o caminho para a imagem E01 na variável `ewf_path` no início do script.
3. Execute o script:

    ```bash
    python maiin.py
    ```

O script irá exibir informações sobre cada partição e calcular os hashes dos arquivos NTUSER.DAT encontrados.

### Funções Principais

- **getOnlyName(entry)**: Retorna o nome do arquivo ou diretório a partir de uma entrada do sistema de arquivos.
- **checkFolders(filesystem)**: Navega pelo diretório `/Users/` e processa arquivos NTUSER.DAT.
- **EWFImgInfo**: Classe personalizada para criar uma interface de imagem virtual a partir do handle EWF.

### Erros Tratados

O script trata diversos tipos de exceções para garantir uma execução suave, incluindo:

- **IOError**: Erros de entrada/saída ao acessar a imagem E01 ou partições.
- **pyewf.error**: Erros específicos da biblioteca pyewf.
- **Exception**: Qualquer outro erro inesperado.

### Exemplo de Saída

```plaintext
Partição: 1, Offset: 1048576, Tamanho: 2147483648, DEC: NTFS
Nome: user1, Tamanho: 5242880
MD5: d41d8cd98f00b204e9800998ecf8427e
SHA-1: da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
