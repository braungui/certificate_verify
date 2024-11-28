import os
from urllib.request import urlopen
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime

# Função para carregar certificados confiáveis de uma pasta
def load_trusted_cas_from_folder(trusted_ca_folder):
    trusted_cas = {}
    for file_name in os.listdir(trusted_ca_folder):
        file_path = os.path.join(trusted_ca_folder, file_name)
        if os.path.isfile(file_path):
            try:
                with open(file_path, "rb") as cert_file:
                    cert_data = cert_file.read()
                    try:
                        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
                    except crypto.Error:
                        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
                    
                    # Guardar o nome do issuer como chave (usando o CN)
                    issuer_name = cert.get_issuer().CN
                    trusted_cas[issuer_name] = cert
                    print(f"CA confiável carregada: {file_name} (Issuer: {issuer_name})")
            except Exception as e:
                print(f"Erro ao carregar certificado {file_name}: {e}")
    return trusted_cas

# Função para buscar certificado intermediário via AIA
def fetch_intermediate_cert_from_aia(cert):
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name().decode() == "authorityInfoAccess":
            aia_data = ext.__str__()
            for line in aia_data.split('\n'):
                if "CA Issuers" in line:
                    url = line.split(' - ')[-1].strip().replace("URI:", "")
                    print(f"Buscando certificado intermediário em: {url}")
                    try:
                        response = urlopen(url)
                        cert_data = response.read()
                        return crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
                    except Exception as e:
                        print(f"Erro ao buscar intermediário pelo AIA: {e}")
    return None

# Construir a cadeia de certificação
def build_cert_chain(user_cert):
    chain = [user_cert]
    while True:
        intermediate_cert = fetch_intermediate_cert_from_aia(chain[-1])
        if intermediate_cert is None:
            break
        chain.append(intermediate_cert)
    return chain

# Verificar se a autoridade certificadora do certificado é confiável
def is_cert_trusted(chain, trusted_cas):
    for cert in chain:
        issuer_name = cert.get_issuer().CN
        if issuer_name in trusted_cas:
            print(f"Certificado confiável. AC correspondente: {issuer_name}")
            return True
    print("Certificado NÃO é confiável. Nenhuma AC correspondente encontrada.")
    return False

# Função para carregar e verificar o CRL com a biblioteca `cryptography`
def verify_crl(cert):
    print("\nVerificando CRL...")
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if ext.get_short_name().decode() == "crlDistributionPoints":
            crl_data = ext.__str__()
            for line in crl_data.split('\n'):
                if "URI:" in line:
                    crl_url = line.split('URI:')[-1].strip()
                    print(f"Baixando CRL em: {crl_url}")
                    try:
                        response = urlopen(crl_url)
                        crl_data = response.read()
                        
                        # Tentar carregar o CRL em formato PEM
                        try:
                            crl = x509.load_pem_x509_crl(crl_data, default_backend())
                        except ValueError:
                            # Se falhar, tentar carregar como DER
                            crl = x509.load_der_x509_crl(crl_data)
                        
                        # Verificar se o certificado está revogado
                        serial_number = cert.get_serial_number()
                        for revoked in crl:
                            if revoked.serial_number == serial_number:
                                print(f"Certificado REVOGADO. Motivo: {revoked.revocation_date}")
                                return False
                        print("Certificado NÃO está revogado.")
                        return True
                    except Exception as e:
                        print(f"Erro ao baixar ou processar a CRL: {e}")
    print("CRL não encontrada ou não disponível.")
    return None

# Verificar validade do certificado com timestamp
def verify_timestamp(cert):
    print("\nVerificando timestamp...")
    not_before = cert.get_notBefore().decode()
    not_after = cert.get_notAfter().decode()
    current_time = datetime.utcnow()
    valid_from = datetime.strptime(not_before, "%Y%m%d%H%M%SZ")
    valid_to = datetime.strptime(not_after, "%Y%m%d%H%M%SZ")
    
    if valid_from <= current_time <= valid_to:
        print("Certificado válido em relação ao tempo.")
        return True
    else:
        print("Certificado FORA do período de validade.")
        return False

# Função principal
def main():
    user_cert_path = input("Digite o caminho do certificado a ser verificado (.crt ou .cer): ").strip()
    trusted_ca_folder = input("Digite o caminho da pasta contendo as ACs confiáveis: ").strip()

    try:
        with open(user_cert_path, "rb") as user_cert_file:
            user_cert_data = user_cert_file.read()
            try:
                user_cert = crypto.load_certificate(crypto.FILETYPE_PEM, user_cert_data)
            except crypto.Error:
                user_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, user_cert_data)
    except Exception as e:
        print(f"Erro ao carregar o certificado do usuário: {e}")
        return

    print("\nConstruindo a cadeia de certificação...")
    chain = build_cert_chain(user_cert)

    print("\nCadeia de certificação:")
    for cert in reversed(chain):
        print(f" - CN Certificado: {cert.get_subject()} | CN certificado superior: {cert.get_issuer()}")

    print("\nCarregando CA confiáveis...")
    trusted_cas = load_trusted_cas_from_folder(trusted_ca_folder)

    print("\nVerificando a confiança do certificado...")
    if is_cert_trusted(chain, trusted_cas):
        print("O certificado é confiável.")
        crl_check = verify_crl(user_cert)
        if crl_check is None or crl_check:  # Verificação continua mesmo que CRL não seja identificada
            if verify_timestamp(user_cert):
                print("O certificado está válido e não foi revogado.")
            else:
                print("O certificado está expirado.")
        else:
            print("O certificado foi revogado.")
    else:
        print("O certificado NÃO é confiável.")

# Executar a aplicação
if __name__ == "__main__":
    main()
