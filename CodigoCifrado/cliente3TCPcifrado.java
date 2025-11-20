package CodigoCifrado;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class cliente3TCPcifrado {

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

            // 1. Recibir clave pública del servidor
            String clavePublicaServidorBase64 = entrada.readLine();
            byte[] bytesClavePublicaServidor = Base64.getDecoder().decode(clavePublicaServidorBase64);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec spec = new X509EncodedKeySpec(bytesClavePublicaServidor);
            clavePublicaServidor = keyFactory.generatePublic(spec);

            // 2. Enviar clave pública del cliente
            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
            generador.initialize(2048);
            KeyPair parClavesCliente = generador.generateKeyPair();
            clavePrivadaCliente = parClavesCliente.getPrivate();

            String clavePublicaClienteBase64 = Base64.getEncoder().encodeToString(parClavesCliente.getPublic().getEncoded());
            salida.println(clavePublicaClienteBase64);

            // 3. Recibir clave AES cifrada y descifrarla con mi RSA privada
            String claveAEScifradaBase64 = entrada.readLine();
            byte[] bytesClaveAEScifrada = Base64.getDecoder().decode(claveAEScifradaBase64);

            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, clavePrivadaCliente);
            byte[] bytesClaveAES = rsaCipher.doFinal(bytesClaveAEScifrada);
            claveAES = new SecretKeySpec(bytesClaveAES, "AES");

            System.out.println(" Intercambio de claves completado (RSA + AES).");
            System.out.println("Comunicación segura iniciada.\n");

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
                    System.out.println(" Conexión cerrada por el servidor.");
                    System.exit(0);
                }
            }).start();

            // Hilo principal para enviar mensajes
            System.out.print("> ");
            while (true) {
                String mensaje = scanner.nextLine();

                // Si el mensaje es salir, lo enviamos cifrado y rompemos el bucle local
                if (mensaje.equalsIgnoreCase("!salir")) {
                    salida.println(safeEncrypt("!salir", claveAES));
                    System.out.println("Desconectado del servidor.");
                    break;
                }

                // CORRECCIÓN: Cifrar el mensaje antes de enviarlo
                String mensajeEncriptado = safeEncrypt(mensaje, claveAES);
                if (mensajeEncriptado != null) {
                    salida.println(mensajeEncriptado);
                }

                System.out.print("> ");
            }

            socket.close();
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Método añadido para encriptar antes de enviar
    private static String safeEncrypt(String mensaje, SecretKey clave) {
        try {
            Cipher aes = Cipher.getInstance("AES");
            aes.init(Cipher.ENCRYPT_MODE, clave);
            return Base64.getEncoder().encodeToString(aes.doFinal(mensaje.getBytes()));
        } catch (Exception e) {
            System.out.println("Error al cifrar mensaje: " + e.getMessage());
            return null;
        }
    }

    private static String safeDecrypt(String mensajeCifrado, SecretKey clave) {
        if (clave == null) return mensajeCifrado;
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, clave);
            byte[] bytesDescifrados = cipher.doFinal(Base64.getDecoder().decode(mensajeCifrado));
            return new String(bytesDescifrados);
        } catch (Exception e) {
            return "(Error de descifrado o mensaje del sistema)";
        }
    }
}
