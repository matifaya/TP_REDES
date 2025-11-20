package CodigoCifrado;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class MensajeEncriptado {

    public static KeyPair generarParRSA() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }


    public static String codificarClavePublica(PublicKey clavePublica) {
        return Base64.getEncoder().encodeToString(clavePublica.getEncoded());
    }


    public static SecretKey descifrarClaveAESRSA(String claveCifrada, PrivateKey privada) throws Exception {
        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, privada);
        byte[] decodificada = Base64.getDecoder().decode(claveCifrada);
        byte[] claveBytes = rsa.doFinal(decodificada);
        return new SecretKeySpec(claveBytes, 0, claveBytes.length, "AES");
    }


    public static String safeEncrypt(String mensaje, SecretKey clave) {
        try {
            Cipher aes = Cipher.getInstance("AES");
            aes.init(Cipher.ENCRYPT_MODE, clave);
            return Base64.getEncoder().encodeToString(aes.doFinal(mensaje.getBytes()));
        } catch (Exception e) {
            return "Error de cifrado";
        }
    }


    public static String safeDecrypt(String mensajeCifrado, SecretKey clave) {
        try {
            Cipher aes = Cipher.getInstance("AES");
            aes.init(Cipher.DECRYPT_MODE, clave);
            byte[] decod = Base64.getDecoder().decode(mensajeCifrado);
            return new String(aes.doFinal(decod));
        } catch (Exception e) {
            return "Error de descifrado";
        }
    }
}
