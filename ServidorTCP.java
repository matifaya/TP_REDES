import java.io.*;
import java.net.*;
import java.util.*;

public class ServidorTCP {
    private static HashMap<String, Socket> clientes = new HashMap<>();

    public static void main(String[] args) throws IOException {
        ServerSocket servidor = new ServerSocket(5000);
        System.out.println("Servidor iniciado en el puerto 5000...");

        while (true) {
            Socket cliente = servidor.accept();
            new Thread(new ManejadorCliente(cliente)).start();
        }
    }

    static class ManejadorCliente implements Runnable {
        private Socket socket;
        private String nombre;

        public ManejadorCliente(Socket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);

                // Pedir nombre
                salida.println("Ingresa tu nombre de usuario:");
                nombre = entrada.readLine();

                synchronized (clientes) {
                    while (clientes.containsKey(nombre)) {
                        salida.println("Ese nombre ya está en uso. Ingresa otro:");
                        nombre = entrada.readLine();
                    }
                    clientes.put(nombre, socket);
                }

                salida.println("Bienvenido " + nombre + ". Usa @usuario mensaje, @todos mensaje o !salir para desconectarte.");

                String mensaje;
                while ((mensaje = entrada.readLine()) != null) {
                    if (mensaje.equalsIgnoreCase("!salir")) {
                        salida.println("Te has desconectado.");
                        break;
                    }

                    if (mensaje.startsWith("@")) {
                        int espacio = mensaje.indexOf(' ');
                        if (espacio != -1) {
                            String destino = mensaje.substring(1, espacio);
                            String contenido = mensaje.substring(espacio + 1);

                            if (destino.equalsIgnoreCase("todos")) {
                                enviarATodos(nombre, contenido);
                            } else {
                                enviarPrivado(nombre, destino, contenido, salida);
                            }
                        }
                    } else {
                        salida.println("Formato incorrecto. Usa @usuario mensaje o @todos mensaje");
                    }
                }
            } catch (IOException e) {
                System.out.println("Cliente desconectado: " + nombre);
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                synchronized (clientes) {
                    clientes.remove(nombre);
                }
                enviarATodos("Servidor", nombre + " se ha desconectado.");
            }
        }

        private void enviarPrivado(String origen, String destino, String mensaje, PrintWriter salidaOrigen) throws IOException {
            Socket socketDestino = clientes.get(destino);
            if (socketDestino != null) {
                PrintWriter salidaDest = new PrintWriter(socketDestino.getOutputStream(), true);
                salidaDest.println("[Privado] " + origen + ": " + mensaje);
            } else {
                salidaOrigen.println("Usuario " + destino + " no encontrado.");
            }
        }

        private void enviarATodos(String origen, String mensaje) {
            synchronized (clientes) {
                for (Map.Entry<String, Socket> entrada : clientes.entrySet()) {
                    try {
                        if (!entrada.getKey().equals(origen)) {
                            PrintWriter salida = new PrintWriter(entrada.getValue().getOutputStream(), true);
                            salida.println("[Global] " + origen + ": " + mensaje);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }
}
