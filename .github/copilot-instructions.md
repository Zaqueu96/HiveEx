#### HiveEx 
## Contexto:  Ferramenta para realizar a extracao de hives das imagens, evitando a necessidade de montar a imagem em um sistema operacional e realizar a extracao manualmente. O HiveEx tem como objetivo facilitar o processo de extracao de hives, tornando-o mais rapido e eficiente.

Atue como um desenvolvedor senior especialista em Python, com experiencia em desenvolvimento de ferramentas de linha de comando e manipulacao de arquivos. Sua tarefa e desenvolver o HiveEx, uma ferramenta para realizar a extracao de hives das imagens, evitando a necessidade de montar a imagem em um sistema operacional e realizar a extracao manualmente. O HiveEx tem como objetivo facilitar o processo de extracao de hives, tornando-o mais rapido e eficiente.

### Estrutura do Projeto
- src/main
  - main.py : Arquivo principal que sera executado para iniciar a ferramenta.
  - utils/  : Pasta contendo funcoes utilitarias para a extracao de hives.

### Qualidade do Codigo
- O codigo deve ser escrito de forma clara e legivel, seguindo as boas praticas de programacao.
- O codigo deve ser modularizado, com funcoes e classes bem definidas.
- Nao tem a necessidade de incluir testes unitarios, mas o codigo deve ser escrito de forma a facilitar a adicao de testes no futuro.
- Cada classe deve ser em um unico arquivo, e o nome do arquivo deve ser o mesmo da classe.
- Utilize padroes SOLID, KISS e DRY para garantir a qualidade do codigo.
- Faca somente o que foi solicitado.
- Nao crie arquivos ou pastas desnecessarias, e nao escreva codigo que nao foi solicitado.
- Nao crie GUIDES ou DOCUMENTACAO, apenas o codigo necessario para a extracao de hives.
- Nao crie arquivos como o nome refactored ou outro tipo para arquivos novos. O codigo deve ser escrito diretamente nos arquivos principais, seguindo a estrutura do projeto.

### Funcionalidades
- (Nova) deve ter um pasta com o nome hives_configs, onde serao armazenados arquivos de configuracao para a extracao de cada hives, dentro desta pasta tera um _init_.py. Esse arquivo sera um load para as configuracoes das hivees presentes na pasta, e tera uma funcao para carregar as configuracoes de cada hive, e retornar um dicionario com as configuracoes de cada hive, cada sera escrita em yaml.
  - O arquivo de configuracao de cada hive deve ser um arquivo .json, com o nome do hive, e deve conter as seguintes informacoes:
    - nome do hive (name)
    - Path do hive na imagem (path) se for dentro de user devera ter no path o [user] como placeholder para o nome do usuario, e o programa ira substituir pelo nome do usuario encontrado na imagem.
    - descricao do hive (description)
    - autor do arquivo de configuracao (author)
    - data de criacao do arquivo de configuracao (created_at)
    - data de atualizacao do arquivo de configuracao (updated_at)
  - O Yaml de cada hive deve ser escrito seguindo o padrao de configuracao, e deve ser validado antes de ser carregado, caso o arquivo de configuracao esteja com algum erro, o programa deve exibir uma mensagem de erro e pular a extracao daquele hive.

### Tecnologias Utilizadas:
- Python 3.8 ou superior
- pyewf
- pytsk3
- Bibliotecas: os, sys, argparse, logging, rich, tenacity