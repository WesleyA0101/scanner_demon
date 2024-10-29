# Scanner Demon

<div align="center">
  <img src="https://media0.giphy.com/media/l2JhnXnR5PvTOPjEs/giphy.webp?cid=790b7611t6cc3o6f93krq4axmx7az7muwsn2x5jo9548ioqh&ep=v1_gifs_search&rid=giphy.webp&ct=g" width="300" height="300" alt="Skull gif"/>
</div>

Scanner Demon é uma ferramenta de escaneamento de redes que permite capturar pacotes, verificar a atividade de hosts e escanear portas em um determinado IP. Desenvolvido em C.

## Criado por WesleyA0101

## Tecnologias usadas

<div align="center">
  <img src="https://icongr.am/devicon/c-original.svg?size=128&color=currentColor" alt="C Logo" width="60" height="60"/>
  <img src="https://icongr.am/devicon/vim-original.svg?size=128&color=currentColor" alt="Vim Logo" width="60" height="60"/>
</div>

## Tabela de Conteúdos

- [Características](#características)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Uso](#uso)

## Características

- **Captura de Pacotes:** Monitore o tráfego da rede em tempo real.
- **Verificação de Hosts:** Descubra quais dispositivos estão ativos em sua rede.
- **Escaneamento de Portas:** Identifique portas abertas e serviços em execução em um IP específico.
- **Relatórios em HTML:** Geração de relatórios de escaneamento formatados para facilitar a visualização.

## Pré-requisitos

Antes de começar, você precisará ter:

- Um sistema operacional baseado em Linux.
- `gcc` e `make` instalados para compilar o código.
- Biblioteca `libpcap` para captura de pacotes.

## Instalação

Clone o repositório e compile o projeto:

```bash
git clone https://github.com/seuusuario/scanner_demon.git
cd scanner_demon
make

ou

gcc scanner_demon.c -o scanner_demon -lpcap -lpthread
```
## Uso

```bash
./scanner_demon
```

