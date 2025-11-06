package CodigoCifrado;

import java.security.*;
import java.util.Base64;

public class FirmaDigital {

    public static String firmarMensaje(String mensaje, PrivateKey clavePrivada) throws Exception {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(clavePrivada);
        firma.update(mensaje.getBytes());
        byte[] firmado = firma.sign();
        return Base64.getEncoder().encodeToString(firmado);
    }

    public static boolean verificarFirma(String mensaje, String firmaBase64, PublicKey clavePublica) throws Exception {
        Signature verif = Signature.getInstance("SHA256withRSA");
        verif.initVerify(clavePublica);
        verif.update(mensaje.getBytes());
        return verif.verify(Base64.getDecoder().decode(firmaBase64));
    }
}
