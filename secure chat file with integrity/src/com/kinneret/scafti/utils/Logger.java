package com.kinneret.scafti.utils;

import com.kinneret.scafti.configuration.Configuration;
import com.kinneret.scafti.server.Server;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import static com.kinneret.scafti.ui.Controller.conf;
import static com.kinneret.scafti.utils.CommonChars.space;
import static com.kinneret.scafti.utils.DateAndTime.getCurrentDateTimeStamp;

public class Logger {

    private static File logger;

    static {
        logger = new File("SCAFTI-Logger.log");
    }

    /**
     * An enum that contains log level types
     */
    public enum LOG_LEVEL {
        INFO,
        DEBUG,
        ERROR
    }

    /**
     * A method to write info to log file
     * @param TAG
     * @param errorMessage
     * @param neighbor
     * @param userName
     * @param type
     * @param message
     * @param iv
     * @param hmac
     */
    public static void writeToLog(LOG_LEVEL TAG, String errorMessage, Configuration.Neighbor neighbor, String userName, Server.MessageType type, String message,
                                  String iv, String hmac) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(logger, true))) {
            if(type == null)//error in decryption or integrity
            {
                bw.write(getCurrentDateTimeStamp() + space + TAG + " - " + "Received Message - " +
                        errorMessage + " content: " + message + ", iv: " + iv + ", hmac: " + hmac + ", valid: FALSE" + "\n");
                bw.newLine();
            }
            else {
                if (neighbor == null) {
                    bw.write(getCurrentDateTimeStamp() + space + TAG + " - " + "Sent Message - " + "ip: " + conf.getIp() +
                            ", port: " + conf.getPort() + ", name: " + userName + " (me) " + ", type: " + type +
                            ", message: " + message + ", iv: " + iv + ", hmac: " + hmac + ", valid: TRUE" + "\n");
                    bw.newLine();
                } else {
                    bw.write(getCurrentDateTimeStamp() + space + TAG + " - " + "Received Message - " + "ip: " + neighbor.getIp() +
                            ", port: " + neighbor.getPort() + ", name: " + userName + ", type: " + type +
                            ", message: " + message + ", iv: " + iv + ", hmac: " + hmac + ", valid: TRUE" + "\n");
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            System.out.println("Error while writing to log");
        }
    }
}
