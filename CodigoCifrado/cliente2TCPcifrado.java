package CodigoCifrado;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class cliente2TCPcifrado {

    private static PublicKey clavePublicaServidor;
    private static PrivateKey clavePrivadaCliente;
    private static SecretKey claveAES;

    public static void main(String[] args) {
        try {
            Socket socket = new Socket("localhost", 5000);
            System.out.println("Conectado al servidor híbrido.\n");

            BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);
            Scanner scanner = new Scanner(System.in);

            // ============================
            // FASE 1: Intercambio RSA
            // ============================

            // 1️⃣ Recibir clave pública del servidor
            String clavePublicaServidorBase64 = entrada.readLine();
            byte[] bytesClavePublicaServidor = Base64.getDecoder().decode(clavePublicaServidorBase64);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec spec = new X509EncodedKeySpec(bytesClavePublicaServidor);
            clavePublicaServidor = keyFactory.generatePublic(spec);

            // 2️⃣ Generar par de claves RSA del cliente
            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
            generador.initialize(2048);
            KeyPair parClavesCliente = generador.generateKeyPair();
            clavePrivadaCliente = parClavesCliente.getPrivate();

            // 3️⃣ Enviar clave pública del cliente al servidor
            String clavePublicaClienteBase64 = Base64.getEncoder().encodeToString(parClavesCliente.getPublic().getEncoded());
            salida.println(clavePublicaClienteBase64);

            // 4️⃣ Recibir clave AES cifrada y descifrarla con la clave privada RSA del cliente
            String claveAEScifradaBase64 = entrada.readLine();
            byte[] bytesClaveAEScifrada = Base64.getDecoder().decode(claveAEScifradaBase64);

            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, clavePrivadaCliente);
            byte[] bytesClaveAES = rsaCipher.doFinal(bytesClaveAEScifrada);
            claveAES = new SecretKeySpec(bytesClaveAES, "AES");

            System.out.println("✅ Intercambio de claves completado (RSA + AES).");
            System.out.println("Comunicación segura iniciada.\n");

            // ============================
            // FASE 2: Comunicación cifrada AES
            // ============================

            // Hilo para recibir mensajes
            new Thread(() -> {
                try {
                    String mensajeRecibido;
                    while ((mensajeRecibido = entrada.readLine()) != null) {
                        String texto = safeDecrypt(mensajeRecibido, claveAES);
                        System.out.println("\n" + texto);
                        System.out.print("> ");
                    }
                } catch (Exception e) {
                    System.out.println("❌ Conexión cerrada por el servidor.");
                }
            }).start();

            // Enviar mensajes
            System.out.print("> ");
            while (true) {
                String mensaje = scanner.nextLine();
                salida.println(mensaje);

                if (mensaje.equalsIgnoreCase("!salir")) {
                    System.out.println("Desconectado del servidor.");
                    break;
                }
                System.out.print("> ");
            }

            socket.close();
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ============================
    // MÉTODOS DE CIFRADO / DESCIFRADO
    // ============================

    private static String decryptAESMessage(String mensajeCifrado, SecretKey clave) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, clave);
        byte[] bytesDescifrados = cipher.doFinal(Base64.getDecoder().decode(mensajeCifrado));
        return new String(bytesDescifrados);
    }

    private static String safeDecrypt(String texto, SecretKey clave) {
        if (clave == null) return texto;
        try {
            return decryptAESMessage(texto, clave);
        } catch (Exception e) {
            // Si el mensaje no está cifrado o el descifrado falla, lo muestra igual
            return texto;
        }
    }
}
