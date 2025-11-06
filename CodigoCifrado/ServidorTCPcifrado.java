package CodigoCifrado;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;

public class ServidorTCPcifrado {

    private static Map<String, Socket> clientes = new HashMap<>();
    private static Map<String, SecretKey> clavesAES = new HashMap<>();
    private static Map<String, Set<String>> grupos = new HashMap<>();

    private static KeyPair parRSA;
    private static PrivateKey clavePrivada;
    private static PublicKey clavePublica;

    public static void main(String[] args) {
        int puerto = 5000; // valor por defecto
        if (args.length > 0) {
            puerto = Integer.parseInt(args[0]);
        }

        try (ServerSocket servidor = new ServerSocket(puerto)) {
            System.out.println("Servidor iniciado en el puerto " + puerto);

            parRSA = MensajeEncriptado.generarParRSA();
            clavePrivada = parRSA.getPrivate();
            clavePublica = parRSA.getPublic();

            while (true) {
                Socket cliente = servidor.accept();
                new Thread(new ManejadorCliente(cliente)).start();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ===================== CLASE MANEJADORA =====================
    static class ManejadorCliente implements Runnable {
        private Socket socket;
        private String nombre;
        private SecretKey claveAES;

        public ManejadorCliente(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                BufferedReader entrada = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                PrintWriter salida = new PrintWriter(socket.getOutputStream(), true);

                // Enviar clave pública al cliente
                salida.println(MensajeEncriptado.codificarClavePublica(clavePublica));

                // Recibir clave AES cifrada
                String claveAEScifrada = entrada.readLine();
                claveAES = MensajeEncriptado.descifrarClaveAESRSA(claveAEScifrada, clavePrivada);

                // Pedir nombre de usuario
                salida.println(MensajeEncriptado.safeEncrypt("Ingresa tu nombre de usuario:", claveAES));
                nombre = MensajeEncriptado.safeDecrypt(entrada.readLine(), claveAES);

                registrarCliente(salida);

                String mensajeCifrado;
                while ((mensajeCifrado = entrada.readLine()) != null) {
                    String mensaje = MensajeEncriptado.safeDecrypt(mensajeCifrado, claveAES);

                    if (mensaje.equalsIgnoreCase("!salir")) {
                        salida.println(MensajeEncriptado.safeEncrypt("Desconectado.", claveAES));
                        break;
                    }

                    procesarMensaje(mensaje, salida);
                }

            } catch (Exception e) {
                System.out.println("Cliente desconectado: " + nombre);
            } finally {
                desconectarCliente();
            }
        }

        // ----------- REGISTRO Y DESCONECCIÓN ----------
        private void registrarCliente(PrintWriter salida) throws Exception {
            synchronized (clientes) {
                while (clientes.containsKey(nombre)) {
                    salida.println(MensajeEncriptado.safeEncrypt("Nombre en uso. Ingresa otro:", claveAES));
                    nombre = MensajeEncriptado.safeDecrypt(
                            new BufferedReader(new InputStreamReader(socket.getInputStream())).readLine(), claveAES);
                }
                clientes.put(nombre, socket);
                clavesAES.put(nombre, claveAES);
            }
            salida.println(MensajeEncriptado.safeEncrypt("Bienvenido " + nombre, claveAES));
            enviarATodos("Servidor", nombre + " se ha conectado.");
        }

        private void desconectarCliente() {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            synchronized (clientes) {
                clientes.remove(nombre);
                clavesAES.remove(nombre);
            }
            enviarATodos("Servidor", nombre + " se ha desconectado.");
        }

        // ----------- PROCESAMIENTO DE MENSAJES ----------
        private void procesarMensaje(String mensaje, PrintWriter salida) throws Exception {
            if (mensaje.startsWith("@")) {
                enviarPrivadoOMasivo(mensaje, salida);
            } else if (mensaje.startsWith("#")) {
                procesarComandoGrupo(mensaje, salida);
            } else {
                salida.println(MensajeEncriptado.safeEncrypt("Comando no reconocido.", claveAES));
            }
        }

        private void enviarPrivadoOMasivo(String mensaje, PrintWriter salida) throws Exception {
            int espacio = mensaje.indexOf(' ');
            if (espacio == -1) {
                salida.println(MensajeEncriptado.safeEncrypt("Formato incorrecto.", claveAES));
                return;
            }

            String destino = mensaje.substring(1, espacio);
            String contenido = mensaje.substring(espacio + 1);

            if (destino.equalsIgnoreCase("todos")) {
                enviarATodos(nombre, contenido);
            } else {
                enviarPrivado(nombre, destino, contenido, salida);
            }
        }

        private void procesarComandoGrupo(String mensaje, PrintWriter salida) throws Exception {
            String[] partes = mensaje.split(" ");
            String comando = partes[0];

            if (comando.equalsIgnoreCase("#crear")) {
                crearGrupo(partes, salida);
            } else if (comando.equalsIgnoreCase("#grupo")) {
                enviarAGrupo(partes, salida);
            } else if (comando.equalsIgnoreCase("#grupos")) {
                listarGrupos(salida);
            } else {
                salida.println(MensajeEncriptado.safeEncrypt("Comando de grupo no válido.", claveAES));
            }
        }

        // ----------- FUNCIONES DE GRUPOS ------------
        private void crearGrupo(String[] partes, PrintWriter salida) throws Exception {
            if (partes.length < 3) {
                salida.println(MensajeEncriptado.safeEncrypt("Uso: #crear nombreGrupo miembro1 miembro2 ...", claveAES));
                return;
            }

            String nombreGrupo = partes[1];
            Set<String> miembros = new HashSet<>(Arrays.asList(partes).subList(2, partes.length));
            miembros.add(nombre); // incluir al creador

            synchronized (grupos) {
                if (grupos.containsKey(nombreGrupo)) {
                    salida.println(MensajeEncriptado.safeEncrypt("El grupo ya existe.", claveAES));
                    return;
                }
                grupos.put(nombreGrupo, miembros);
            }

            salida.println(MensajeEncriptado.safeEncrypt("Grupo '" + nombreGrupo + "' creado.", claveAES));
        }

        private void enviarAGrupo(String[] partes, PrintWriter salida) throws Exception {
            if (partes.length < 3) {
                salida.println(MensajeEncriptado.safeEncrypt("Uso: #grupo nombreGrupo mensaje", claveAES));
                return;
            }

            String nombreGrupo = partes[1];
            String contenido = String.join(" ", Arrays.copyOfRange(partes, 2, partes.length));

            if (!grupos.containsKey(nombreGrupo)) {
                salida.println(MensajeEncriptado.safeEncrypt("Grupo no encontrado.", claveAES));
                return;
            }

            for (String miembro : grupos.get(nombreGrupo)) {
                if (!miembro.equals(nombre) && clientes.containsKey(miembro)) {
                    PrintWriter salidaMiembro = new PrintWriter(clientes.get(miembro).getOutputStream(), true);
                    salidaMiembro.println(MensajeEncriptado.safeEncrypt(
                            "[Grupo " + nombreGrupo + "] " + nombre + ": " + contenido, clavesAES.get(miembro)));
                }
            }
        }

        private void listarGrupos(PrintWriter salida) throws Exception {
            StringBuilder sb = new StringBuilder("Grupos existentes:\n");
            for (String g : grupos.keySet()) {
                sb.append("- ").append(g).append("\n");
            }
            salida.println(MensajeEncriptado.safeEncrypt(sb.toString(), claveAES));
        }

        // ----------- FUNCIONES DE ENVÍO ------------
        private void enviarPrivado(String origen, String destino, String mensaje, PrintWriter salidaOrigen) throws Exception {
            Socket socketDestino = clientes.get(destino);
            if (socketDestino != null) {
                PrintWriter salidaDest = new PrintWriter(socketDestino.getOutputStream(), true);
                salidaDest.println(MensajeEncriptado.safeEncrypt("[Privado] " + origen + ": " + mensaje, clavesAES.get(destino)));
            } else {
                salidaOrigen.println(MensajeEncriptado.safeEncrypt("Usuario " + destino + " no encontrado.", clavesAES.get(origen)));
            }
        }

        private void enviarATodos(String origen, String mensaje) {
            synchronized (clientes) {
                clientes.forEach((nombreCli, sock) -> {
                    if (!nombreCli.equals(origen)) {
                        try {
                            PrintWriter salida = new PrintWriter(sock.getOutputStream(), true);
                            salida.println(MensajeEncriptado.safeEncrypt("[Global] " + origen + ": " + mensaje, clavesAES.get(nombreCli)));
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
            }
        }
    }
}
