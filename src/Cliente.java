import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import java.math.BigInteger;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Cliente {
    public static final int SOCKET = 4030;
    public static final String SERVER = "localhost";



    public static void main(String[] args) throws Exception {
        Socket socket = null;
        PrintWriter writer = null;
        BufferedReader reader = null;
        SecurityFunctions f = new SecurityFunctions();

        System.out.println("Cliente ...");

        try {
            // Crea el socket en el lado cliente
            socket = new Socket(SERVER, SOCKET);

            // Connects the Client with the server
            writer = new PrintWriter(socket.getOutputStream(), true);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));


        } catch (Exception e) {

            e.printStackTrace();
            System.exit(-1);
        }


        // 1. Sends the initial message to the server
        writer.println("SECURE INIT");


        /**
         * 3
         */
        BigInteger g = new BigInteger(reader.readLine());



        BigInteger p = new BigInteger(reader.readLine());


        BigInteger g2x = new BigInteger(reader.readLine());

        /**
         * 4) Verificar F(K_w-, (G,P,G^x))
         */
        String authentication = reader.readLine();
        // Calculates the value of X, which is a random number between 1 and p-1
        byte[] authenticationAsBytes = str2byte(authentication);
        PublicKey publicKey = f.read_kplus("datos_asim_srv.pub", "Cliente");
        String message = g.toString() + "," + p.toString() + "," + g2x.toString();

        if (f.checkSignature(publicKey, authenticationAsBytes, message)) {
            /**
             * 5
             */
            writer.println("OK");
        } else {
            writer.println("ERROR");
        }

        BigInteger x = Cliente.nextRandomBigInteger(p);

        /**
         * 6a
         */
        BigInteger ourY = g.modPow(x, p);
        writer.println(ourY);



        /**
         * 7a
         */

        // Calculates the master key
        BigInteger z = g2x.modPow(x, p);



        // Generates the symmetric key to cipher the message (K_AB1)
        SecretKey K_AB1 = f.csk1(z.toString());


        // Generates the symmetric key for the HMAC (K_AB2)
        SecretKey K_AB2 = f.csk2(z.toString());


        byte[] iv1 = generateIvBytes();
        IvParameterSpec iv1Sepc = new IvParameterSpec(iv1);



        /**
         * 8
         */
        // // Message from user input
        // System.out.println("Introduce el mensaje a enviar (debe ser un número): ");
        // BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        // String consulta = stdIn.readLine();
        // byte[] consultaBytes = str2byte(consulta);
        // stdIn.close(); // Closes the BufferedReader
        // if (strIsNumeric(consulta)) {
        // writer.println(consulta);
        // System.out.println("Consulta del usuario: " + consulta);
        // } else {
        // System.err.println("La consulta no es un número");
        // System.exit(-1);
        // }
        int consulta = 99; // TODO: Consulta

        byte[] consultaBytes = str2byte(consulta + "");

        // Encrypts the message C(K_AB1, <consulta>)
        byte[] encryptedConsulta = f.senc(consultaBytes, K_AB1, iv1Sepc, "Hola");
        writer.println(byte2str(encryptedConsulta));

        // HMAC of the message HMAC(K_AB2, <consulta>)
        byte[] hmacConsulta = f.hmac(consultaBytes, K_AB2);
        writer.println(byte2str(hmacConsulta));

        // IV of the message
        writer.println(byte2str(iv1));

        /**
         * 10
         */
        String respuesta = reader.readLine();
        if (respuesta == null || respuesta.equals("ERROR")) {
            writer.flush();
            System.err.println(
                    "Error en la consulta 9 de C(K_AB1<consulta>) y HMAC(K_AB2,<consulta>)");
            System.exit(-1);
        }

        /**
         * 11) Recieve the encrypted message C(K_AB1, <respuesta>)
         */
        String encryptedRespuesta = reader.readLine();
        byte[] encryptedRespuestaBytes = str2byte(encryptedRespuesta);

        String hmacRespuesta = reader.readLine();
        byte[] hmacRespuestaBytes = str2byte(hmacRespuesta);

        String iv2Respuesta = reader.readLine();
        byte[] iv2RespuestaBytes = str2byte(iv2Respuesta);
        IvParameterSpec iv2Spec = new IvParameterSpec(iv2RespuestaBytes);

        // Decrypts the message C(K_AB1, <respuesta>)
        // String K_AB1_2 = K_AB1.toString() + "1";
        // SecretKey K_AB1_2_SecretKey = f.csk1(K_AB1_2);
        byte[] descifrado = f.sdec(encryptedRespuestaBytes, K_AB1, iv2Spec);
        System.out.println("Respuesta del servidor: " + byte2str(descifrado));
        // TODO: Ver por qué verificar retorna false
        boolean verificar = f.checkInt(descifrado, K_AB2, hmacRespuestaBytes);
        if (verificar && Integer.parseInt(byte2str(descifrado)) == consulta + 1) {
            writer.println("OK");
            System.out.println("La respuesta es correcta");
        } else {
            writer.println("ERROR");
            System.out.println("La respuesta es incorrecta");
        }
        reader.close();
        writer.flush();
        writer.close();
        socket.close();
    }


    /**
     * Checks if a string is a number
     * 
     * @param str
     * @return
     */
    public static boolean strIsNumeric(String str) {
        try {
            Double.parseDouble(str);
        } catch (NumberFormatException nfe) {
            return false;
        }
        return true;
    }


    /**
     * This method calculates the value of X, which is a random number between 1 and p-1
     * 
     * @param p
     * @return
     */
    private static BigInteger nextRandomBigInteger(BigInteger p) {
        Random rand = new Random();
        BigInteger x = new BigInteger(p.bitLength(), rand);

        while (x.compareTo(p) >= 0) {
            x = new BigInteger(p.bitLength(), rand);
        }
        return x;
    }



    public static byte[] str2byte(String ss) {
        // Encapsulamiento con hexadecimales
        byte[] ret = new byte[ss.length() / 2];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) Integer.parseInt(ss.substring(i * 2, (i + 1) * 2), 16);
        }
        return ret;
    }

    public static String byte2str(byte[] b) {
        // Encapsulamiento con hexadecimales
        String ret = "";
        for (int i = 0; i < b.length; i++) {
            String g = Integer.toHexString(((char) b[i]) & 0x00ff);
            ret += (g.length() == 1 ? "0" : "") + g;
        }
        return ret;
    }

    /**
     * Generates the initialization vecto
     * 
     * @return iv
     */
    private static byte[] generateIvBytes() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

}
