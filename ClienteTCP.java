import java.io.*;
import java.net.*;

public class ClienteTCP {
    public static void main(String[] args) throws IOException {
        Socket socket = new Socket("127.0.0.1", 5000); // Cambia IP si es otra PC
        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
        BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);

        // Hilo para recibir mensajes
        new Thread(() -> {
            try {
                String mensaje;
                while ((mensaje = entrada.readLine()) != null) {
                    System.out.println(mensaje);
                }
            } catch (IOException e) {
                System.out.println("Desconectado del servidor");
            }
        }).start();

        // Enviar mensajes hasta que escriba "!salir"
        String linea;
        while ((linea = teclado.readLine()) != null) {
            salida.println(linea);
            if (linea.equalsIgnoreCase("!salir")) {
                System.out.println("Desconectando...");
                socket.close();
                System.exit(0);
            }
        }
    }
}
