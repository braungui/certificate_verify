O código funciona da seguinte forma:

1. Em primeiro momento, será solicitado ao usuário que insira o caminho do certificado que deseja verificar:
EXEMPLO: C:/user/Desktop/certificado.cer

2. A seguir, será solicitada a inserção do diretório contendo os certificados das entidades confiáveis (RootCA's das entidades confiáveis),
a estrutura desse código foi pensada na utilização de uma pasta, que contenham os certificados das entidades para verificação.

Após isso, não será necessária a inserção de mais nenhuma informação, o script fará a análise do certificado.

Bibliotecas necessárias:
Pyopenssl:
-pip install pyopenssl
Cryptography:
-pip install cryptography
