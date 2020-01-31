package com.kinneret.scafti.server.files;

import com.kinneret.scafti.client.Client;
import com.kinneret.scafti.configuration.Configuration;
import com.kinneret.scafti.ui.Controller;
import com.kinneret.scafti.ui.Main;
import com.kinneret.scafti.utils.Logger;
import javafx.application.Platform;
import javafx.scene.control.Alert;
import javafx.util.Pair;

import java.io.*;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.kinneret.scafti.security.Security.decryptFile;
import static com.kinneret.scafti.server.HandleClientThread.getNeighborByIpPort;
import static com.kinneret.scafti.server.Server.MessageType.*;
import static com.kinneret.scafti.utils.CommonChars.COLON;
import static com.kinneret.scafti.utils.CommonChars.SLASH;
import static com.kinneret.scafti.utils.Logger.writeToLog;

/**
 * A class represented a thread that listen to the client files
 */
public class HandleFileTransferThread extends Thread {

    private Socket clientSocket;
    private boolean stop = false;
    private Configuration.Neighbor neighbor;
   private AtomicBoolean succeed = new AtomicBoolean(false);
   private boolean isIntegrityOk;

    HandleFileTransferThread(Socket socket) {
        this.clientSocket = socket;
    }

    /**
     * A method that the thread will run when starts
     */
    @Override
    public void run() {
        System.out.println("Received connection from: " + clientSocket);
        try (InputStream in = clientSocket.getInputStream();
             BufferedReader br = new BufferedReader(new InputStreamReader(in))) {
            String input;

            while (!stop) {
                input = br.readLine();
                if ((input != null) && (!input.trim().isEmpty()) && (!stop)) {
                    processFile(input);
                }
            }
            if (succeed.get()) {
                Client.sendToNeighbor(ACK, Controller.userName + " Received the file successfully", neighbor);
            } else {
                if(isIntegrityOk) {
                    Client.sendToNeighbor(OK, Controller.userName + " Canceled file saving after receiving it", neighbor);
                } else {
                    Client.sendToNeighbor(FAILED, Controller.userName + " Did not receive the file, because the file is corrupted", neighbor);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * A method to process an incoming encrypted file
     * @param encryptedFile - the encrypted file to process
     */
    private void processFile(String encryptedFile) {
        Pair<String, byte[]> decryptedFile = decryptFile(encryptedFile);
        if (decryptedFile == null) {
            stop = true;
            return;
        }
        String[] tokens = decryptedFile.getKey().trim().split(SLASH);
        String[] ipPort = tokens[0].trim().split(COLON);
        String hmacDigest = tokens[1].trim();
        String hmacResult = tokens[2].trim();
        String iv = tokens[3].trim();
        String fileName = tokens[4].trim();
        isIntegrityOk = hmacResult.equals("true");
        neighbor= getNeighborByIpPort(ipPort[0], ipPort[1]);

        if(!isIntegrityOk)
        {
            succeed.set(false);
            stop = true;
            Platform.runLater(() ->
                    Main.controller.showMessageBox("File Transfer",
                            "File transfer completed successfully, but the file is illegal or corrupted", Alert.AlertType.ERROR));
            writeToLog(Logger.LOG_LEVEL.ERROR, "Integrity error, probably due to corrupted file or wrong mac key.",
                    neighbor, neighbor.getName(), null, "", iv, hmacDigest);
            return;
        }

        Platform.runLater(() -> {
            File receivedFile = Main.controller.chooseDirectory(fileName);
            if (receivedFile != null) {
                try (FileOutputStream fos = new FileOutputStream(receivedFile)) {
                    fos.write(decryptedFile.getValue());
                } catch (IOException e) {
                    e.printStackTrace();
                }
                Main.controller.showMessageBox("File Transfer", "File transfer completed successfully", Alert.AlertType.INFORMATION);
                succeed.set(true);
            }
            stop = true;
        });
    }
}
