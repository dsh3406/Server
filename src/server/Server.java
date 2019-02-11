/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import com.sun.xml.internal.messaging.saaj.packaging.mime.util.BASE64DecoderStream;
import com.sun.xml.internal.messaging.saaj.packaging.mime.util.BASE64EncoderStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import static java.lang.System.exit;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Formatter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Server {

    private static Cipher ecipher;
    private static Cipher dcipher;

    private static SecretKey key;
    private static final String HMAC_SHA1 = "HmacSHA1";

    public static void main(String[] args) throws Exception {

        String filepath = "key.txt";
        String algo = "HMACSHA1";
        Mac mac = Mac.getInstance(algo);

        //  read from file
        FileInputStream fileIn = new FileInputStream(filepath);
        ObjectInputStream objectIn = new ObjectInputStream(fileIn);
        key = (SecretKey) objectIn.readObject();
        mac.init(key);

        System.out.println(key.toString());

        System.out.println("The server is running.");
        int clientNumber = 0;
        ServerSocket listener = new ServerSocket(9898);
        try {
            while (true) {
                new Capitalizer(listener.accept(), clientNumber++).start();
            }
        } finally {
            listener.close();
        }
    }

    /**
     * A private thread to handle capitalization requests on a particular
     * socket. The client terminates the dialogue by sending a single line
     * containing only a period.
     */
    private static class Capitalizer extends Thread {

        private Socket socket;
        private int clientNumber;

        public Capitalizer(Socket socket, int clientNumber) {
            this.socket = socket;
            this.clientNumber = clientNumber;
            log("New connection with client# " + clientNumber + " at " + socket);
        }

        public void run() {
            try {

                BufferedReader in = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));
                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

                // Send a welcome message to the client.
                out.println("Hello, you are client #" + clientNumber + ".");
                out.println("Enter a line with only a period to quit\n");

                // Get messages from the client, line by line;  decrypt message check hmac then return the message encrypted for the client to encrypt it
                // 
                while (true) {
                    String input = in.readLine();
                    
                    if (input == null || input.equals(".")) {
                        break;
                    }

                    dcipher = Cipher.getInstance("DES");
                    dcipher.init(Cipher.DECRYPT_MODE, key);
                    String decrypted = decrypt(input);
                    //System.out.println(decrypted);

                    String hmac = decrypted.substring(0, 40);
                    String message = decrypted.substring(40, decrypted.length());

                    String check = calculateHMAC(message, "key");

                    if (check.equals(hmac)) {
                        System.out.println("Hmac:" + hmac + " is the same. The message has not changed in transit from client.\n");
                    } else {
                        System.out.println("not the same hmac.\n");
                    }

                    
                    System.out.println("Message received:" + message);
                    out.println(input);
                }
            } catch (IOException e) {
                log("Error handling client# " + clientNumber + ": " + e);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SignatureException ex) {
                Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    log("Couldn't close a socket, what's going on?");
                }
                log("Connection with client# " + clientNumber + " closed");
            }
        }

        /**
         * Logs a simple message. In this case we just write the message to the
         * server applications standard output.
         */
        private void log(String message) {
            System.out.println(message);
        }

    }

    public static String encrypt(String str) {

        try {

            // encode the string into a sequence of bytes using the named charset
            // storing the result into a new byte array. 
            byte[] utf8 = str.getBytes("UTF8");

            byte[] enc = ecipher.doFinal(utf8);

// encode to base64
            enc = BASE64EncoderStream.encode(enc);

            return new String(enc);

        } catch (Exception e) {

            e.printStackTrace();

        }

        return null;

    }

    public static String decrypt(String str) {

        try {

            // decode with base64 to get bytes
            byte[] dec = BASE64DecoderStream.decode(str.getBytes());

            byte[] utf8 = dcipher.doFinal(dec);

// create new string based on the specified charset
            return new String(utf8, "UTF8");

        } catch (Exception e) {

            e.printStackTrace();

        }

        return null;

    }

    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    public static String calculateHMAC(String data, String key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), HMAC_SHA1);
        Mac mac = Mac.getInstance(HMAC_SHA1);
        mac.init(secretKeySpec);
        return toHexString(mac.doFinal(data.getBytes()));
    }

}
