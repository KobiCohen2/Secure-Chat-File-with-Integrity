package com.kinneret.scafti.client;

import com.kinneret.scafti.configuration.Configuration;
import com.kinneret.scafti.ui.Controller;
import com.kinneret.scafti.server.Server;
import com.kinneret.scafti.utils.Logger;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import static com.kinneret.scafti.ui.Controller.conf;
import static com.kinneret.scafti.security.Security.*;
import static com.kinneret.scafti.security.Security.encryptMessage;
import static com.kinneret.scafti.server.Server.FILE_SERVER_PORT_SHIFTING;
import static com.kinneret.scafti.server.Server.MessageType.*;
import static com.kinneret.scafti.utils.CommonChars.*;
import static com.kinneret.scafti.utils.Logger.writeToLog;

/**
 * A class represent client
 */
public class Client {

    /**
     * A map to hold the open socket for each neighbor in the multi-cast
     */
    public static Map<Configuration.Neighbor, Socket> connectedNeighborsMap = Collections.synchronizedMap(new HashMap<>());

    /**
     *A method to send messages to all neighbors in the multi-cast
     * @param type - the type of the message
     * @param message - the content of the message
     */
    public static void sendToNeighbors(Server.MessageType type, String message) {
        String encryptedMessage;
        String iv = "";
        String hmac = "";
        for (Socket socket: connectedNeighborsMap.values()) {
            try {
                PrintWriter printWriter = new PrintWriter(socket.getOutputStream());
                switch (type) {
                    case HELLO:
                        encryptedMessage = encryptMessage(HELLO + space + Controller.userName +
                                space + conf.getIp() + space + conf.getPort());
                        iv = encryptedMessage.split(SEPARATOR)[1];
                        hmac = encryptedMessage.split(SEPARATOR)[2];
                        printWriter.write(encryptedMessage + newLine);
                        break;
                    case MESSAGE:
                        encryptedMessage = encryptMessage(MESSAGE + space + Controller.userName +
                                space + conf.getIp() + space + conf.getPort() + space + message);
                        iv = encryptedMessage.split(SEPARATOR)[1];
                        hmac = encryptedMessage.split(SEPARATOR)[2];
                        printWriter.write(encryptedMessage + newLine);
                        break;
                    case BYE:
                        encryptedMessage = encryptMessage(BYE + space + Controller.userName +
                                space + conf.getIp() + space + conf.getPort());
                        iv = encryptedMessage.split(SEPARATOR)[1];
                        hmac = encryptedMessage.split(SEPARATOR)[2];
                        printWriter.write(encryptedMessage + newLine);
                        break;
                }
                printWriter.flush();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        writeToLog(Logger.LOG_LEVEL.INFO, "", null, Controller.userName, type, message, iv, hmac);
    }

    /**
     * A method to send messages to specific neighbor in the multi-cast
     * @param type - the type of the message
     * @param message - the content of the message
     * @param neighbor - the neighbor to whom the message will be sent
     */
    public static void sendToNeighbor(Server.MessageType type, String message, Configuration.Neighbor neighbor)
    {
        String encryptedMessage;
        String iv = "";
        String hmac = "";
            try {
                PrintWriter printWriter = new PrintWriter(connectedNeighborsMap.get(neighbor).getOutputStream());
                encryptedMessage = encryptMessage(type + space + Controller.userName +
                                space + conf.getIp() + space + conf.getPort() + space + message);
                iv = encryptedMessage.split(SEPARATOR)[1];
                hmac = encryptedMessage.split(SEPARATOR)[2];
                printWriter.write(encryptedMessage + newLine);
                printWriter.flush();
            } catch (Exception e) {
                e.printStackTrace();
        }
        writeToLog(Logger.LOG_LEVEL.INFO, "", null, Controller.userName, type, message, iv, hmac);
    }

    /**
     * A method to send file request message to specific neighbor in the multi-cast
     * @param neighbor - the neighbor to whom the message will be sent
     * @param fileName - the name of the file
     */
    public static void sendFileRequestToNeighbor(Configuration.Neighbor neighbor, String fileName) {
        Socket socket = connectedNeighborsMap.get(neighbor);
        try {
            PrintWriter printWriter = new PrintWriter(socket.getOutputStream());
            String encryptedMessage = encryptMessage(SENDFILE + space + Controller.userName +
                    space + conf.getIp() + space + conf.getPort() + space + fileName);
            printWriter.write(encryptedMessage + newLine);
            printWriter.flush();
            writeToLog(Logger.LOG_LEVEL.INFO, "", null, Controller.userName, SENDFILE, fileName,
                    encryptedMessage.split(SEPARATOR)[1], encryptedMessage.split(SEPARATOR)[2]);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * A method to send a file to specific neighbor in the multi-cast
     * @param neighbor - the neighbor to whom the message will be sent
     * @param file - the file to send
     */
    public static void sendFileToNeighbor(Configuration.Neighbor neighbor, File file) {
        try (Socket socket = new Socket(neighbor.getIp(), Integer.parseInt(neighbor.getPort()) + FILE_SERVER_PORT_SHIFTING)) {
            PrintWriter printWriter = new PrintWriter(socket.getOutputStream());
            printWriter.write(encryptFile(file) + newLine);
            printWriter.flush();
            printWriter.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * A method to start client
     */
    public static void connectClient() {
        conf.getNeighbors().forEach(neighbor -> {
            try {
                Socket socket = new Socket(neighbor.getIp(), Integer.parseInt(neighbor.getPort()));
                PrintWriter printWriter = new PrintWriter(socket.getOutputStream());
                String message = HELLO + space + Controller.userName + space + conf.getIp() + space + conf.getPort();
                String encryptedMessage = encryptMessage(message);
                printWriter.write(encryptedMessage + newLine);
                printWriter.flush();
                writeToLog(Logger.LOG_LEVEL.INFO, "", null, Controller.userName, HELLO, message,
                        encryptedMessage.split(SEPARATOR)[1], encryptedMessage.split(SEPARATOR)[2]);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        Controller.isConnected = true;
    }

    /**
     * A method to disconnect client
     */
    public static void disconnectClient() {
       connectedNeighborsMap.values().forEach(socket -> {
           try {
               socket.close();
           } catch (IOException e) {
               e.printStackTrace();
           }
       });
       connectedNeighborsMap.clear();
    }
}