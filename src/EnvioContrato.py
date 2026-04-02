import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature


def gerar_par_chaves():
    """Gera um par de chaves RSA de 2048 bits para uma empresa."""
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    chave_publica = chave_privada.public_key()
    return chave_privada, chave_publica

#Empresa A: Envio de contrato
def preparar_envio_seguro(documento_bytes, chave_publica_destinatario, chave_privada_remetente):
    print("\n[Empresa A] A iniciar a preparação do contrato para envio seguro...")
    
    chave_simetrica_aes = os.urandom(32)
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(chave_simetrica_aes), modes.GCM(iv))
    encryptor = cipher.encryptor()
    documento_criptografado = encryptor.update(documento_bytes) + encryptor.finalize()
    tag_autenticacao = encryptor.tag 
    
    chave_aes_criptografada = chave_publica_destinatario.encrypt(
        chave_simetrica_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    pacote_dados = chave_aes_criptografada + iv + tag_autenticacao + documento_criptografado
    assinatura_digital = chave_privada_remetente.sign(
        pacote_dados,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    print("[Empresa A] Documento criptografado, chave simétrica protegida e pacote assinado digitalmente.")
    
    return {
        "chave_simetrica_criptografada": chave_aes_criptografada,
        "iv": iv,
        "tag": tag_autenticacao,
        "documento_criptografado": documento_criptografado,
        "assinatura": assinatura_digital
    }

#Empresa B: Recepção e validação do contrato
def receber_e_validar_contrato(pacote, chave_publica_remetente, chave_privada_destinatario):
    print("\n[Empresa B] Pacote recebido. A iniciar o processo de validação e descriptografia...")
    
    pacote_dados = pacote["chave_simetrica_criptografada"] + pacote["iv"] + pacote["tag"] + pacote["documento_criptografado"]
    
    try:
        chave_publica_remetente.verify(
            pacote["assinatura"],
            pacote_dados,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("[Empresa B] [SUCESSO] Assinatura digital válida. Autenticidade e integridade confirmadas.")
    except InvalidSignature:
        print("[Empresa B] [ERRO] Assinatura digital inválida! O documento foi alterado ou a origem é fraudulenta.")
        return None

    chave_aes_recuperada = chave_privada_destinatario.decrypt(
        pacote["chave_simetrica_criptografada"],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    cipher = Cipher(algorithms.AES(chave_aes_recuperada), modes.GCM(pacote["iv"], pacote["tag"]))
    decryptor = cipher.decryptor()
    documento_original = decryptor.update(pacote["documento_criptografado"]) + decryptor.finalize()
    
    print("[Empresa B] [SUCESSO] Documento descriptografado com sucesso.")
    return documento_original

#Fluxo de demonstração
if __name__ == "__main__":
    print("=== PLATAFORMA SECUREDOCS: DEMONSTRAÇÃO DO SISTEMA ===\n")

    privada_A, publica_A = gerar_par_chaves()
    privada_B, publica_B = gerar_par_chaves()
    print("[*] Pares de chaves RSA gerados para a Empresa A e Empresa B.")

    texto_contrato = "CONTRATO DE PARCERIA ESTRATÉGICA. Valor: 1.000.000 EUR. Cláusula de confidencialidade estrita."
    contrato_bytes = texto_contrato.encode('utf-8')
    print("[*] Contrato original criado em memória.")

    pacote_transmitido = preparar_envio_seguro(contrato_bytes, publica_B, privada_A)

    documento_recuperado = receber_e_validar_contrato(pacote_transmitido, publica_A, privada_B)

    if documento_recuperado == contrato_bytes:
        print(f"\n[RESULTADO] A transmissão segura foi concluída com êxito. Conteúdo lido: '{documento_recuperado.decode('utf-8')}'")
    
    #Teste de integridade: Simulação de interceção e modificação do contrato
    print("\n=== SIMULAÇÃO DE INTERCEÇÃO (MODIFICAÇÃO DO CONTRATO) ===")
    
    pacote_adulterado = pacote_transmitido.copy()
    dados_corrompidos = bytearray(pacote_adulterado["documento_criptografado"])
    dados_corrompidos[0] = dados_corrompidos[0] ^ 0xFF
    pacote_adulterado["documento_criptografado"] = bytes(dados_corrompidos)
    
    print("[Atacante] Um byte do documento criptografado foi modificado na rede.")

    receber_e_validar_contrato(pacote_adulterado, publica_A, privada_B)