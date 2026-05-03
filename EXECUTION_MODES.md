# HiveEx - Modos de Execução

## 🎯 Modo Automático (Padrão)

Quando você executa sem argumentos, **a GUI abre automaticamente**:

```bash
# Abre a GUI automaticamente
python hivex.py

# Equivalente a:
python hivex.py --gui
python src/main/main.py
```

## 💻 Modo CLI (Linha de Comando)

Quando você passa argumentos, executa em **modo CLI**:

```bash
# Extrair SAM de uma imagem
python hivex.py --image image.E01 --sam

# Extrair múltiplas imagens com config
python hivex.py -img img1.E01 -img img2.E01 --config sam --config system

# Listar configurações disponíveis
python hivex.py --list-configs -v

# Ver ajuda
python hivex.py --help
```

## 🔄 Modo GUI Explícito

Você também pode forçar a GUI mesmo com argumentos:

```bash
# Abre a GUI (ignora outros argumentos)
python hivex.py --gui
python hivex.py -g
```

## 📊 Tabela de Comportamento

| Comando | Modo | Descrição |
|---------|------|-----------|
| `python hivex.py` | GUI | Sem argumentos → GUI automática |
| `python hivex.py --gui` | GUI | Explicitamente GUI |
| `python hivex.py -g` | GUI | Forma curta GUI |
| `python hivex.py --help` | CLI | Mostra ajuda do CLI |
| `python hivex.py -img img.E01 --sam` | CLI | Executa extração CLI |
| `python hivex.py --list-configs` | CLI | Lista configs no CLI |

## 🎛️ Quando Usar Cada Modo

### GUI 
- ✅ Peritos forenses não-técnicos
- ✅ Interfaces visuais intuitivas
- ✅ Seleção gráfica de arquivos
- ✅ Monitoramento visual em tempo real

### CLI
- ✅ Scripts e automação
- ✅ Processamento em batch
- ✅ Integração com outras ferramentas
- ✅ Acesso remoto (SSH)

## 📝 Exemplos Práticos

### Cenário 1: Perito abre a ferramenta sem saber o que fazer
```bash
$ python hivex.py
# → GUI abre automaticamente, usuário pode clicar e selecionar
```

### Cenário 2: Script de automação em batch
```bash
#!/bin/bash
for image in /forensics/images/*.E01; do
    python hivex.py --image "$image" --all --output /forensics/extracted/
done
```

### Cenário 3: Processamento rápido de múltiplas imagens
```bash
python hivex.py \
    --image evidence1.E01 \
    --image evidence2.E01 \
    --image evidence3.E01 \
    --config sam \
    --config system \
    --output /case_output/
```

