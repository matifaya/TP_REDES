package CodigoCifrado;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.*;

public class ServidorTCPcifrado {

    private static final Map<String, Socket> clientes = new HashMap<>();
    private static final Map<String, SecretKey> clavesAES = new HashMap<>();
    private static final Map<String, Set<String>> grupos = new HashMap<>();

    private static KeyPair parRSA;
    private static PrivateKey clavePrivada;
    private static PublicKey clavePublica;

    public static void main(String[] args) {
        int puerto = 5000;
        try (ServerSocket servidor = new ServerSocket(puerto)) {
            System.out.println("=== SERVIDOR INICIADO EN PUERTO " + puerto + " ===");

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

                // Handshake
                salida.println(MensajeEncriptado.codificarClavePublica(clavePublica));
                String cpClienteBase64 = entrada.readLine();
                if (cpClienteBase64 == null) return;

                byte[] bytesCP = Base64.getDecoder().decode(cpClienteBase64);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey pkCliente = kf.generatePublic(new X509EncodedKeySpec(bytesCP));

                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                SecretKey aes = kg.generateKey();
                claveAES = aes;

                Cipher rsa = Cipher.getInstance("RSA");
                rsa.init(Cipher.ENCRYPT_MODE, pkCliente);
                salida.println(Base64.getEncoder().encodeToString(rsa.doFinal(aes.getEncoded())));

                System.out.println("Conexión segura: " + socket.getRemoteSocketAddress());

                // Registro
                salida.println(MensajeEncriptado.safeEncrypt("Ingresa tu usuario:", claveAES));
                String nombreCifrado = entrada.readLine();
                if (nombreCifrado == null) return;

                nombre = MensajeEncriptado.safeDecrypt(nombreCifrado, claveAES).trim();
                registrarCliente(salida);

                // Loop Mensajes
                String linea;
                while ((linea = entrada.readLine()) != null) {
                    String mensaje = MensajeEncriptado.safeDecrypt(linea, claveAES);
                    if (mensaje.equalsIgnoreCase("!salir")) break;
                    procesarMensaje(mensaje, salida);
                }

            } catch (Exception e) {
                System.out.println("Error con " + nombre + ": " + e.getMessage());
            } finally {
                desconectarCliente();
            }
        }

        private void registrarCliente(PrintWriter salida) throws Exception {
            synchronized (clientes) {
                while (clientes.containsKey(nombre)) {
                    salida.println(MensajeEncriptado.safeEncrypt("Nombre ocupado. Otro:", claveAES));
                    String n = new BufferedReader(new InputStreamReader(socket.getInputStream())).readLine();
                    nombre = MensajeEncriptado.safeDecrypt(n, claveAES).trim();
                }
                clientes.put(nombre, socket);
                clavesAES.put(nombre, claveAES);
            }
            salida.println(MensajeEncriptado.safeEncrypt("Bienvenido " + nombre, claveAES));
            System.out.println("Usuario REGISTRADO: " + nombre);
        }

        private void desconectarCliente() {
            try { if (socket != null) socket.close(); } catch (IOException e) {}
            synchronized (clientes) {
                if (nombre != null) {
                    clientes.remove(nombre);
                    clavesAES.remove(nombre);
                }
            }
            if (nombre != null) System.out.println("Usuario DESCONECTADO: " + nombre);
        }

        private void procesarMensaje(String mensaje, PrintWriter salida) throws Exception {
            System.out.println("CMD de " + nombre + ": " + mensaje);

            if (mensaje.startsWith("@")) {
                enviarPrivadoOMasivo(mensaje, salida);
            } else if (mensaje.startsWith("#")) {
                procesarComandoGrupo(mensaje, salida);
            } else {
                salida.println(MensajeEncriptado.safeEncrypt("Comando desconocido.", claveAES));
            }
        }

        private void enviarPrivadoOMasivo(String mensaje, PrintWriter salida) throws Exception {
            String[] partes = mensaje.split("\\s+", 2);
            if (partes.length < 2) return;

            String destino = partes[0].substring(1);
            String contenido = partes[1];

            if (destino.equalsIgnoreCase("todos")) {
                enviarATodos(nombre, contenido);
            } else {
                enviarPrivado(nombre, destino, contenido, salida);
            }
        }

        private void procesarComandoGrupo(String mensaje, PrintWriter salida) throws Exception {
            String[] partes = mensaje.trim().split("\\s+");
            String comando = partes[0];

            if (comando.equalsIgnoreCase("#crear")) {
                crearGrupo(partes, salida);
            } else if (comando.equalsIgnoreCase("#grupo")) {
                enviarAGrupo(partes, salida);
            } else if (comando.equalsIgnoreCase("#grupos")) {
                listarGrupos(salida);
            }
        }

        // --- CORRECCIÓN IMPORTANTE AQUÍ ---
        private void crearGrupo(String[] partes, PrintWriter salida) throws Exception {
            if (partes.length < 3) {
                salida.println(MensajeEncriptado.safeEncrypt("Uso: #crear <Grupo> <User1> <User2>...", claveAES));
                return;
            }

            String nombreGrupo = partes[1];
            Set<String> miembros = new HashSet<>();
            miembros.add(nombre); // Agregar al creador automáticamente

            // Recorrer argumentos y limpiar comas
            for (int i = 2; i < partes.length; i++) {
                // Si el usuario puso "pedro,juan", esto lo separa en "pedro" y "juan"
                String[] subnombres = partes[i].split(",");
                for (String sub : subnombres) {
                    String usuarioLimpio = sub.trim();
                    if (!usuarioLimpio.isEmpty()) {
                        miembros.add(usuarioLimpio);
                    }
                }
            }

            synchronized (grupos) {
                if (grupos.containsKey(nombreGrupo)) {
                    salida.println(MensajeEncriptado.safeEncrypt("El grupo ya existe.", claveAES));
                    return;
                }
                grupos.put(nombreGrupo, miembros);
            }

            salida.println(MensajeEncriptado.safeEncrypt("Grupo '" + nombreGrupo + "' creado.", claveAES));
            System.out.println("NUEVO GRUPO: " + nombreGrupo + " Miembros: " + miembros);
        }

        private void enviarAGrupo(String[] partes, PrintWriter salida) throws Exception {
            if (partes.length < 3) {
                salida.println(MensajeEncriptado.safeEncrypt("Uso: #grupo <Grupo> <Mensaje>", claveAES));
                return;
            }

            String nombreGrupo = partes[1];
            String contenido = String.join(" ", Arrays.copyOfRange(partes, 2, partes.length));

            Set<String> miembros;
            synchronized (grupos) {
                miembros = grupos.get(nombreGrupo);
            }

            if (miembros == null) {
                salida.println(MensajeEncriptado.safeEncrypt("Grupo no encontrado.", claveAES));
                return;
            }

            // Verificación estricta
            if (!miembros.contains(nombre)) {
                salida.println(MensajeEncriptado.safeEncrypt("No estás en este grupo.", claveAES));
                // Depuración para ver por qué falló
                System.out.println("FALLO GRUPO: Usuario '" + nombre + "' intentó hablar en '" + nombreGrupo + "' pero los miembros son: " + miembros);
                return;
            }

            for (String miembroDestino : miembros) {
                if (miembroDestino.equals(nombre)) continue;

                Socket socketDest;
                SecretKey claveDest;
                synchronized (clientes) {
                    socketDest = clientes.get(miembroDestino);
                    claveDest = clavesAES.get(miembroDestino);
                }

                if (socketDest != null && claveDest != null) {
                    try {
                        PrintWriter salidaDest = new PrintWriter(socketDest.getOutputStream(), true);
                        salidaDest.println(MensajeEncriptado.safeEncrypt(
                                "[Grupo " + nombreGrupo + "] " + nombre + ": " + contenido, claveDest));
                    } catch (Exception e) { }
                }
            }
        }

        private void listarGrupos(PrintWriter salida) throws Exception {
            StringBuilder sb = new StringBuilder("Grupos:\n");
            synchronized (grupos) {
                for (String g : grupos.keySet()) {
                    sb.append("- ").append(g).append(" ").append(grupos.get(g)).append("\n");
                }
            }
            salida.println(MensajeEncriptado.safeEncrypt(sb.toString(), claveAES));
        }

        private void enviarPrivado(String origen, String destino, String mensaje, PrintWriter salidaOrigen) throws Exception {
            Socket s;
            SecretKey k;
            synchronized (clientes) {
                s = clientes.get(destino);
                k = clavesAES.get(destino);
            }
            if (s != null) {
                new PrintWriter(s.getOutputStream(), true).println(
                        MensajeEncriptado.safeEncrypt("[Privado] " + origen + ": " + mensaje, k));
            } else {
                salidaOrigen.println(MensajeEncriptado.safeEncrypt("Usuario no encontrado.", clavesAES.get(origen)));
            }
        }

        private void enviarATodos(String origen, String mensaje) {
            synchronized (clientes) {
                clientes.forEach((n, s) -> {
                    if (!n.equals(origen)) {
                        try {
                            new PrintWriter(s.getOutputStream(), true).println(
                                    MensajeEncriptado.safeEncrypt("[Global] " + origen + ": " + mensaje, clavesAES.get(n)));
                        } catch (Exception e) {}
                    }
                });
            }
        }
    }
}
