/**
 * Program Name : Security Protocol for MEC Service Migration - TTP Server
 * Version : FINAL
 * Authors : P.S.Ranaweera
 *
 * Language : Java
 * Date : 06/06/2022
 * */


package StandardProtocol;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.security.*;
import java.math.*;
import java.util.*;

import static java.lang.System.exit;


public class TTP_Server {

    static int TTP_PORT = 1000;         //TTP Running Port
    static int TTP_M_PORT = 1500;       //TTP Migration Port created for the gNBr communication
    static int S_PORT = 900;

    String S_ID, R_ID;
    String OSS_ID;
    String TTP_ID = "192.168.10.1";

    public static long Start_time;
    public static long End_time;
    public static long Process_time;
    public static long Received_time;
    public static long Sending_time;
    public static long Current_time;
    public static long Entity_Start_time;
    public static long ClockSkew = 5000;    //Defined Clock Skew : 5 seconds
    public static long Delta_TS;
    public static long ReceivedTS;
    public static long T_TTP_B, T_TTP_D;

    public static String encryptedString;

    //public String[] MP_IDs;
    public String MP_ID_Array;

    public static String Plaintext;
    public static int RSA_Key_length = 4096; //bits
    public static int AES_Key_Length = 256; //bits
    public static int ECDH_Key_Length_1 = 256; //bits
    public static int ECDH_Key_Length_2 = 128; //bits
    public static int ECDH_Key_Length_3 = 112; //bits
    public static int K_DoS = 3;

    public final String K_dos_TTP = "4";

    public PublicKey publicKey_OSS_CA, publicKey_gNBs, publicKey_gNBr, publicKey_OCC_MVR, publicKey_TTP;

    public PrivateKey privateKey_TTP, verifyingKey_gNBs;

    public static String Common_RSA_Certificate_Path = "E:/OneDrive/PhD Ireland/PhD Work/MEC/Research Directions/Service Migration Prediction/Implementation/MECMigrationProtocol/out/production/MECMigrationProtocol/";

    public static String Entity_gNBs = "gNBs", Entity_gNBr = "gNBr", Entity_OSS_CA = "OSS_CA", Entity_OSS_MVR = "OSS_MVR", Entity_TTP = "TTP";

    public static String RSA_Private_Key_File_Name, RSA_Public_Key_File_Name;

    //AES Variables
    public static SecretKeySpec AES_secretKey;
    public static byte[] AES_key;
    public static byte[] iv;

    //ECDH VAriables

    public static KeyPair kpB, kpC1, kpD;
    public static String PB1, PB2, PD1, PD2, PC1, PC2;

    //Secret Key and Salt for the AESEncrypt() and AESDecrypt() Functions
    public static String SECRET_KEY;
    public static final String SALT = "ssshhhhhhhhhhh!!!!";

    private ServerSocket listener;

    public String n_r, M_CODE;

    public InetAddress S_IP_Address;

    public String n_s, n_ttp, X;

    public BigInteger r1, r2, r1_dash, r2_dash, N;

    // Define color constants
    public static final String TEXT_RESET = "\u001B[0m";
    public static final String TEXT_BLACK = "\u001B[30m";
    public static final String TEXT_RED = "\u001B[31m";
    public static final String TEXT_GREEN = "\u001B[32m";
    public static final String TEXT_YELLOW = "\u001B[33m";
    public static final String TEXT_BLUE = "\u001B[34m";
    public static final String TEXT_PURPLE = "\u001B[35m";
    public static final String TEXT_CYAN = "\u001B[36m";
    public static final String TEXT_WHITE = "\u001B[37m";

    public String input;
    public static boolean exit = false;
    public int ProtocolMsgCount;
    public int SignatureFailCount;
    public int NonceVerifierCount;
    public boolean PuzzleVerified = false;
    public String ACKNOWLEDGEMENT;

    public static int N_Messages = 7;
    public static int N_Trials = 22;

    public static Long[] EST; //Entity Start Time
    public static Long[][] PET; //Process End Time ==> Indicating the end time of each processed message prior to transmission
    public static Long[][] TST; //Transmission Start Time ==> Indicating the starting time at the sender end
    public static Long[][] TET; //Transmission End Time ==> Indicating the received time time at the receiver end
    public static Long[] EET; //Entity End Time

    public int loop_No = 0;

    //Constructor

    public TTP_Server() throws IOException,NoSuchAlgorithmException,InvalidKeySpecException,Exception {

        //Loading the RSA keys of this Entity
        RSA_load_own_keys(Common_RSA_Certificate_Path,Entity_TTP);

        publicKey_gNBs = RSA_load_public_key(Common_RSA_Certificate_Path,Entity_gNBs);

        publicKey_gNBr = RSA_load_public_key(Common_RSA_Certificate_Path,Entity_gNBr);

        System.out.println("\n\n RSA KEY LOADING IS CONCLUDED.........%%%%%%%%%%%%%%%%%% \n\n");

        //verifyingKey_gNBs = RSA_load_Verifying_key(Common_RSA_Certificate_Path,Entity_gNBs);

        //Creation of the ServerSocket
        ServerSocket serverSocket = new ServerSocket(TTP_PORT);

        EST = new Long[N_Trials];
        PET = new Long[N_Trials][N_Messages];
        TST = new Long[N_Trials][N_Messages];
        TET = new Long[N_Trials][N_Messages];
        EET = new Long[N_Trials];

        try {

            while (true) {

                VerticalSpace();
                System.out.println(TEXT_BLUE+"INITIATING the MEC Service Migration AAA Service.................."+TEXT_RESET);

                SignatureFailCount = 0;
                NonceVerifierCount = 0;
                ProtocolMsgCount = 0;
                PuzzleVerified = false;
                exit = false;
                String[] MP_IDs;


                VerticalSpace();

                Socket socket = serverSocket.accept();

                Entity_Start_time = System.nanoTime();

                try {

                    System.out.println(TEXT_BLUE+"Source gNB (gNBs) is Connected to the TTP SERVER ...........\n"+getCurrentTimestamp()+"\n\n"+TEXT_RESET);

                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));


                    while(exit == false) {

                        if (ProtocolMsgCount % 2 == 0) {
                            input = in.readLine();
                        }

                        //%%%%%%%%%%%%%%%%%%%%%%%%%%%   Message 1   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                        if (ProtocolMsgCount == 0) {

                            Received_time = System.nanoTime();
                            TET[loop_No][0] = Received_time;
                            System.out.println("Message 1 from gNBs: " + input + " received at.." + new Timestamp(Received_time));

                            String Message_1[] = input.split(" ");
                            String EncryptedPayload_1 = Message_1[1];
                            String stringSignature_1 = Message_1[2];
                            System.out.println("Encrypted Payload : " + EncryptedPayload_1);
                            String DecryptedPayload_1 = RSA_decrypt(EncryptedPayload_1, privateKey_TTP);
                            System.out.println("Decrypted Payload : " + DecryptedPayload_1);

                            String[] DecryptedPayloadArray_1 = DecryptedPayload_1.split(" ");

                            ReceivedTS = new Long(DecryptedPayloadArray_1[2]);
                            Delta_TS = CheckTS(ReceivedTS, Received_time);

                            System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                            if (Delta_TS <= ClockSkew) {

                                System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);

                                String HMAC_1 = Hash(DecryptedPayloadArray_1[0]+ DecryptedPayloadArray_1[1] + TTP_ID + ReceivedTS);

                                System.out.println("Received HMAC 1: " + Message_1[3]);

                                System.out.println("Formed HMAC 1: " + HMAC_1);

                                if (CheckHash(Message_1[3], HMAC_1)) {
                                    System.out.println(TEXT_GREEN + "The Hashed MACs are MATCHING ==> INTEGRITY SECURED.............." + TEXT_RESET);

                                    S_ID = DecryptedPayloadArray_1[0];
                                    String VerifyingSignature_1 = Hash(TTP_ID + " " + ReceivedTS);

                                    if (RSA_verify(VerifyingSignature_1, stringSignature_1, publicKey_gNBs)) {
                                        System.out.println(TEXT_GREEN + "Signatures are Matching..............." + TEXT_RESET);

                                        System.out.println(TEXT_BLUE + S_ID + " is recorded for a possible migration......." + TEXT_RESET);
                                        PB1 = DecryptedPayloadArray_1[1];
                                        System.out.println("PB1 : "+PB1);

                                        ProtocolMsgCount =1;

                                        VerticalSpace();

                                        System.out.println("%%%%%%%%%%%%%%%%%%%%%% MESSAGE 1 COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                                        PET[loop_No][0] = System.nanoTime();

                                    } else {
                                        System.out.println(TEXT_RED + "Signatures Does not match..............." + TEXT_RESET);
                                        System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED..............." + TEXT_RESET);

                                        out.println("RETRANSMIT_B0");

                                        SignatureFailCount++;
                                        if (SignatureFailCount == 3) exit(0);
                                    }
                                } else{
                                        System.out.println(TEXT_RED + "The Hashed MACs are NOT MATCHING ==> INTEGRITY VIOLATED.............." + TEXT_RESET);
                                        System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                                        out.println("RETRANSMIT_B0");
                                }

                            } else {

                                System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                                System.out.println(TEXT_RED + "DISCARD MESSAGE................." + TEXT_RESET);

                            }

                            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 2  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                        }else if((ProtocolMsgCount == 1)||(input.startsWith("RETRANSMIT_B1"))){

                            n_ttp = RandomNonceGenerator();
                            System.out.println("Generated TTP Nonce : " + n_ttp);
                            PB2 = Generate_ECDH_SharingKey_B(ECDH_Key_Length_1);

                            //Signature Creation
                            Current_time = System.nanoTime();
                            String Pre_Signature_2 = Hash(S_ID + " " + Current_time);
                            String Signature_2 = RSA_sign(Pre_Signature_2, privateKey_TTP);

                            //Payload Creation
                            String Payload_2 = "TTP_MR_REP" + " " + K_DoS + " " + n_ttp + " " + PB2 + " " + Current_time;
                            System.out.println("Signature : " + Signature_2);
                            System.out.println("Size of the Signature : " + Signature_2.length());

                            String HMAC_2 = Hash(K_DoS + n_ttp + PB2 + S_ID + Current_time);
                            byte[] EncryptedPayloadBytes_2 = RSA_encrypt(Payload_2, publicKey_gNBs);
                            String EncryptedPayload_2 = Base64.getEncoder().encodeToString(EncryptedPayloadBytes_2);
                            System.out.println("Encrypted Payload 2 : " + EncryptedPayload_2);
                            String Message_2 = EncryptedPayload_2 + " " + Signature_2 + " " + HMAC_2;
                            PET[loop_No][1] = System.nanoTime();

                            out.println(Message_2);

                            Sending_time = System.nanoTime();
                            TST[loop_No][0] = Sending_time;
                            System.out.println("Message 2 : " + Message_2);
                            System.out.println("Hash length [bytes]: " + HMAC_2.getBytes().length);
                            System.out.println("Payload 2 length [bytes]: " + Payload_2.getBytes().length);
                            System.out.println("Message 2 length [bytes]: " + Message_2.getBytes().length);
                            System.out.println("Message 2 Sent at " + new Timestamp(Sending_time));

                            ProtocolMsgCount = 2;
                            VerticalSpace();

                        //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 3  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
                        }else if(ProtocolMsgCount == 2) {

                            Received_time = System.nanoTime();
                            TET[loop_No][1] = Received_time;
                            System.out.println("Message 3 from gNBs: " + input + " received at.." + new Timestamp(Received_time));
                            String Message_3[] = input.split(" ");
                            String EncryptedPayload_3 = Message_3[0];
                            System.out.println("Encrypted Payload : " + EncryptedPayload_3);
                            String DecryptedPayload_3 = RSA_decrypt(EncryptedPayload_3, privateKey_TTP);
                            System.out.println("Decrypted Payload : " + DecryptedPayload_3);
                            String[] DecryptedPayloadArray_3 = DecryptedPayload_3.split(" ");

                            ReceivedTS = new Long(DecryptedPayloadArray_3[4]);

                            Delta_TS = CheckTS(ReceivedTS, Received_time);

                            System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                            if (Delta_TS <= ClockSkew) {

                                System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);
                                X = DecryptedPayloadArray_3[2];
                                n_s = DecryptedPayloadArray_3[1];

                                String HMAC_3 = Hash(n_s + X + DecryptedPayloadArray_3[3] + ReceivedTS);
                                System.out.println("Received HMAC 3: " + Message_3[1]);
                                System.out.println("Formed HMAC 3: " + HMAC_3);

                                if (CheckHash(Message_3[1], HMAC_3)) {

                                    //DoS PUZZLE VERIFIER
                                    DoS_Puzzle_Verification(K_DoS, publicKey_gNBs.toString(), S_ID, TTP_ID, n_s, n_ttp, X);

                                    if(PuzzleVerified == true){
                                        //TTP Nonce Verifier
                                        if (DecryptedPayloadArray_3[3].equals(Hash(n_ttp + ReceivedTS))) {
                                            System.out.println(TEXT_GREEN+"S Nonce is Verified..............."+TEXT_RESET);
                                            VerticalSpace();

                                            System.out.println("%%%%%%%%%%%%%%%%%%%%%% MESSAGE 3 COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                                            PET[loop_No][2] = System.nanoTime();
                                            ProtocolMsgCount = 3;
                                            VerticalSpace();

                                        } else {
                                            System.out.println(TEXT_RED+"S Nonce is NOT Verified..............."+TEXT_RESET);
                                            System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                                            out.println("RETRANSMIT_B2");
                                            NonceVerifierCount++;
                                            if (NonceVerifierCount == 3) exit(0);
                                        }
                                    }else{
                                        System.out.println(TEXT_RED+"DoS PUZZLE NOT Verified ==> Possible DoS Threat..........."+TEXT_RESET);
                                        System.out.println(TEXT_RED+"DISCARD MESSAGE................."+TEXT_RESET);
                                        exit(0);
                                    }
                                } else {
                                    System.out.println(TEXT_RED + "The Hashed MACs are NOT MATCHING ==> INTEGRITY VIOLATED.............." + TEXT_RESET);
                                    System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                                    out.println("RETRANSMIT_B2");
                                }
                            } else {

                                System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                                System.out.println(TEXT_RED + "DISCARD MESSAGE................." + TEXT_RESET);
                            }

                        //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 4  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
                        }else if((ProtocolMsgCount == 3)||(input.startsWith("RETRANSMIT_B3"))) {

                            //Migration Key Parameter Generation
                            Migration_Key__Parameter_Generation(16);

                            //Creating the MP_ID_Array
                            MP_ID_Array = MP_ID_ArrayGeneration(5);
                            System.out.println("MP ID ARRAY : " + MP_ID_Array);
                            //MP_IDs = MP_ID_Array.split("SPACE");

                            SECRET_KEY = Create_ECDH_SecretKey(PB1,PB2,kpB);
                            //SECRET_KEY = SECRET_KEY.substring(0, Math.min(SECRET_KEY.length(), 8));
                            System.out.println("Secret Key : "+SECRET_KEY);
                            System.out.println("Secret Key Length: "+SECRET_KEY.length());

                            Current_time = System.nanoTime();
                            String Hashed_Nonce_S = Hash256(n_s + Current_time);

                            //AES Payload
                            String SecretPayload_4 = TTP_M_PORT + "SPLIT" + MP_ID_Array + "SPLIT" + r1_dash;
                            String EncryptedSecretPayload_4 = AES_Encrypt(SecretPayload_4);
                            System.out.println("Secret Payload : "+EncryptedSecretPayload_4);
                            System.out.println("Secret Payload Size: "+EncryptedSecretPayload_4.length());


                            //Payload Creation
                            String Payload_4 = "TTP_MR_REP_1" + "SPLIT" + EncryptedSecretPayload_4 + "SPLIT" + Hashed_Nonce_S + "SPLIT" + Current_time;
                            String HMAC_4 = Hash(TTP_M_PORT + MP_ID_Array + r1_dash + n_s + Current_time);
                            byte[] EncryptedPayloadBytes_4 = RSA_encrypt(Payload_4, publicKey_gNBs);
                            String EncryptedPayload_4 = Base64.getEncoder().encodeToString(EncryptedPayloadBytes_4);
                            System.out.println("Encrypted Payload 4 : " + EncryptedPayload_4);
                            String Message_4 = EncryptedPayload_4 + " " + HMAC_4;
                            PET[loop_No][3] = System.nanoTime();

                            out.println(Message_4);
                            Sending_time = System.nanoTime();
                            TST[loop_No][1] = System.nanoTime();

                            System.out.println("Message 4 : " + Message_4);
                            System.out.println("Hash length [bytes]: " + HMAC_4.getBytes().length);
                            System.out.println("Payload 4 length [bytes]: " + Payload_4.getBytes().length);
                            System.out.println("Message 4 length [bytes]: " + Message_4.getBytes().length);
                            System.out.println("Message 4 Sent at " + new Timestamp(Sending_time));
                            ProtocolMsgCount = 4;

                        }else if(input.startsWith("COMPLETE_B")){

                            System.out.println(input);

                            VerticalSpace();

                            T_TTP_B = System.nanoTime();

                            System.out.println("Time taken for the conclusion of PROTOCOL SEGMENT B (T_B) [ms]: "+CheckTS(Entity_Start_time,T_TTP_B));
                            System.out.println(TEXT_BLUE+"%%%%%%%%%%%%%%%%%%%%%% PROTOCOL SEGMENT B COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n"+TEXT_RESET);
                            exit = true;
                            VerticalSpace();

                        }else{
                            System.out.println(TEXT_PURPLE+"MESSAGE NOT RECOGNIZED.............==> DISCARDED"+TEXT_RESET);
                            VerticalSpace();
                        }

                    }

                    in.close();
                    out.close();
                    //socket.close();

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  gNBr COMMUNICATION  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 1 and Message 2  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    MP_IDs = MP_ID_Array.split("SPACE");

                    //Function for Listening to gNBr
                    startListening(TTP_M_PORT,MP_IDs);

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  gNBs COMMUNICATION  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Final Message to gNBs with M_CODE  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    S_IP_Address = InetAddress.getLocalHost();
                    Socket S_socket = new Socket(S_IP_Address,S_PORT);

                    in = new BufferedReader(new InputStreamReader(S_socket.getInputStream()));
                    out = new PrintWriter(S_socket.getOutputStream(), true);

                    exit = false;

                    while(exit == false) {

                        PC2 = Generate_ECDH_SharingKey_C(ECDH_Key_Length_3);
                        SECRET_KEY = Create_ECDH_SecretKey(PC1,PC2,kpC1);

                        Current_time = System.nanoTime();
                        String S_SecretPayload_1 = M_CODE+ " " +r2_dash;
                        String S_EncryptedSecretPayload_1 = AES_Encrypt(S_SecretPayload_1);
                        System.out.println("Secret Payload Size :"+S_EncryptedSecretPayload_1.length());

                        //Payload Creation
                        String S_Payload_1 = TTP_ID + " " + MP_IDs[0] + " " + PC2 + " " + S_EncryptedSecretPayload_1 + " " + Current_time;
                        System.out.println("Size of the Payload : "+S_Payload_1.length());

                        //String S_HMAC_1 = Hash(TTP_ID + MP_IDs[0] + PC2 + M_CODE + r2_dash + Current_time);
                        byte[] S_EncryptedPayloadBytes_1 = RSA_encrypt(S_Payload_1, publicKey_gNBs);
                        String S_EncryptedPayload_1 = Base64.getEncoder().encodeToString(S_EncryptedPayloadBytes_1);
                        System.out.println("Encrypted Payload 1 : " + S_EncryptedPayload_1);
                        String S_Message_1 = "TTP_SV_VER" + " " + S_EncryptedPayload_1;
                        PET[loop_No][6] = System.nanoTime();

                        out.println(S_Message_1);

                        Sending_time = System.nanoTime();
                        TST[loop_No][3] = Sending_time;
                        System.out.println("Message 1 : " + S_Message_1);
                        //System.out.println("Hash length [bytes]: " + S_HMAC_1.getBytes().length);
                        System.out.println("Payload 1 length [bytes]: " + S_Payload_1.getBytes().length);
                        System.out.println("Message 1 length [bytes]: " + S_Message_1.getBytes().length);
                        System.out.println("Message 1 Sent at " + new Timestamp(Sending_time));

                        input = in.readLine();

                        if(input.equals("ACK_D2")){
                            exit = true;
                        }
                    }

                    System.out.println("%%%%%%%%%%%%%%%%%%  TTP SERVER OPERATIONS ARE CONCLUDED  %%%%%%%%%%%%%%%%%%%%%%%%");

                    VerticalSpace();

                    T_TTP_D = System.nanoTime();

                    System.out.println("Time taken for the conclusion of PROTOCOL SEGMENT D (T_D) [ms]: "+CheckTS(T_TTP_B,T_TTP_D));

                    loop_No++;

                    //Flushing the MP_IDs Array
                    for (int x = 0; x < MP_IDs.length; x++) {

                        MP_IDs[x] = " ";
                    }

                    in.close();
                    out.close();
                    S_socket.close();

                } finally {
                    socket.close();
                }

                System.out.println("Displaying the Timing Values................\n\n\n");

                for(int x = 0; x < loop_No; x++){
                    System.out.println("TET : ");
                    for(int y = 0; y < 3; y++){
                        System.out.print(", "+TET[x][y]);
                    }
                    System.out.println();
                }

                for(int x = 0; x < loop_No; x++){
                    System.out.println("TST : ");
                    for(int y = 0; y < 3; y++){
                        System.out.print(", "+TST[x][y]);
                    }
                    System.out.println();
                }

                for(int x = 0; x < loop_No; x++){
                    System.out.println("PET : ");
                    for(int y = 0; y < 6; y++){
                        System.out.print(", "+PET[x][y]);
                    }
                    System.out.println();
                }

            }

        } finally {
            serverSocket.close();

        }


    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException,InvalidKeySpecException,Exception {

        System.out.println("The MEC SERVICE MIGRATION TRUSTED THIRD PARTY AAA SERVER is Running................\n\n\n");

        TTP_Server ttp_server = new TTP_Server();

    }


    private ServerSocket CreateListeningSocket(int port){
        ServerSocket serverSocket = null;

        try
        {
            serverSocket = new ServerSocket( port );
        }
        catch ( IOException e )
        {
            e.printStackTrace();
        }

        return serverSocket;

    }

    private void startListening(int port, String[] MP_IDs)throws IOException {
        listener = CreateListeningSocket(port);
        //acceptedSocket = es.submit( new ServAccept( listener ) );
        Socket serverSocket = listener.accept();

        BufferedReader in = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
        PrintWriter out = new PrintWriter(serverSocket.getOutputStream(), true);

        SignatureFailCount = 0;
        NonceVerifierCount = 0;
        ProtocolMsgCount = 0;
        exit = false;

        try {

            while(exit == false) {

                //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 1  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                if(ProtocolMsgCount % 2 == 0) {
                    input = in.readLine();
                }
                //%%%%%%%%%%%%%%%%%%%%%%%%%%%   Message 1   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                if (ProtocolMsgCount == 0) {

                    Received_time = System.nanoTime();
                    TET[loop_No][2] = Received_time;
                    String R_Message_1[] = input.split(" ");
                    String R_MIH = R_Message_1[0];

                    if (Check_MIH(R_MIH, "R_SV_REQ")) {
                        System.out.println(TEXT_GREEN+"MIHs are matching in the Received Message..............."+TEXT_RESET);
                        R_ID = R_Message_1[1];
                        String R_EncryptedPayload_1 = R_Message_1[2];
                        String R_stringSignature_1 = R_Message_1[3];
                        System.out.println("Encrypted Payload : " + R_EncryptedPayload_1);
                        String R_DecryptedPayload_1 = RSA_decrypt(R_EncryptedPayload_1, privateKey_TTP);
                        System.out.println("Decrypted Payload : " + R_DecryptedPayload_1);
                        String[] R_DecryptedPayloadArray_1 = R_DecryptedPayload_1.split(" ");

                        ReceivedTS = new Long(R_DecryptedPayloadArray_1[5]);
                        Delta_TS = CheckTS(ReceivedTS, Received_time);
                        System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                        if (Delta_TS <= ClockSkew) {
                            System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);
                            n_r = R_DecryptedPayloadArray_1[2];
                            System.out.println("MP ID : "+MP_IDs[0]);
                            PC1 = R_DecryptedPayloadArray_1[3];
                            PD1 = R_DecryptedPayloadArray_1[4];

                            String R_HMAC_1 = Hash(TTP_ID + MP_IDs[0] + n_r + PC1 + PD1 + ReceivedTS);
                            System.out.println("Received HMAC 1: " + R_Message_1[4]);
                            System.out.println("Formed HMAC 1: " + R_HMAC_1);

                            if (CheckHash(R_Message_1[4], R_HMAC_1)) {
                                System.out.println(TEXT_GREEN + "The Hashed MACs are MATCHING ==> INTEGRITY SECURED.............." + TEXT_RESET);

                                if (Check_ID(R_DecryptedPayloadArray_1[0], TTP_ID)) {
                                    System.out.println(TEXT_GREEN+"TTP IDs are matching in the Received Message..............."+TEXT_RESET);

                                    if (Check_ID(R_DecryptedPayloadArray_1[1], MP_IDs[0])) {
                                        System.out.println(TEXT_GREEN+"Received Migration Process IDs are matching..............."+TEXT_RESET);

                                        String R_VerifyingSignature_1 = Hash(TTP_ID + " " + ReceivedTS);
                                        if (RSA_verify(R_VerifyingSignature_1, R_stringSignature_1, publicKey_gNBr)) {
                                            System.out.println(TEXT_GREEN + "Signatures are Matching..............." + TEXT_RESET);

                                            System.out.println(TEXT_BLUE + R_ID + " is confirmed for migration......." + TEXT_RESET);
                                            System.out.println("gNBr Verified for the Migration Process ID : " + MP_IDs[0]);

                                            System.out.println("Received PC1: " + PC1);
                                            System.out.println("Received PD1: " + PD1);
                                            VerticalSpace();
                                            ProtocolMsgCount = 1;

                                            System.out.println("%%%%%%%%%%%%%%%%%%%%%% MESSAGE 1 COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                                            PET[loop_No][4] = System.nanoTime();

                                        } else {
                                            System.out.println(TEXT_RED + "Signatures Does not match..............." + TEXT_RESET);
                                            System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED..............." + TEXT_RESET);

                                            out.println("RETRANSMIT_D0");

                                            SignatureFailCount++;
                                            if (SignatureFailCount == 3) exit(0);
                                        }
                                    } else System.out.println(TEXT_RED+"MP IDs DO NOT MATCH..............."+TEXT_RESET);

                                } else System.out.println(TEXT_RED+"TTP IDs DO NOT MATCH..............."+TEXT_RESET);
                            } else {
                                System.out.println(TEXT_RED + "The Hashed MACs are NOT MATCHING ==> INTEGRITY VIOLATED.............." + TEXT_RESET);
                                System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                                out.println("RETRANSMIT_D0");
                            }
                        } else {

                            System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                            System.out.println(TEXT_RED + "DISCARD MESSAGE................." + TEXT_RESET);
                        }
                    } else System.out.println(TEXT_RED+"MIHs Does not match..............."+TEXT_RESET);

                }else if((ProtocolMsgCount == 1)||(input.startsWith("RETRANSMIT_D1"))) {

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 2  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    String RAND = RandomNonceGenerator();
                    M_CODE = Hash(MP_IDs[0] + TTP_M_PORT + TTP_ID + S_ID + R_ID + privateKey_TTP.toString() + RAND + Current_time);
                    System.out.println("M CODE : " + M_CODE);

                    PD2 = Generate_ECDH_SharingKey_D(ECDH_Key_Length_3);

                    SECRET_KEY = Create_ECDH_SecretKey(PD1,PD2,kpD);
                    System.out.println("Secret Key : "+SECRET_KEY);
                    System.out.println("Secret Key Length: "+SECRET_KEY.length());

                    //Signature Creation
                    Current_time = System.nanoTime();
                    String Hashed_Nonce_R = Hash128(n_r + Current_time);
                    String Pre_Signature_2 = Hash(S_ID + Current_time);
                    String Signature_2 = RSA_sign(Pre_Signature_2, privateKey_TTP);

                    //String SecretPayload_2 = M_CODE+" "+r1+" "+r2+" "+N;
                    String SecretPayload_2 = M_CODE+" "+r1+" "+r2+" "+N+ " " + Hashed_Nonce_R;
                    String EncryptedSecretPayload_2 = AES_Encrypt(SecretPayload_2);
                    System.out.println("Secret Payload : "+EncryptedSecretPayload_2);
                    System.out.println("Secret Payload Size: "+EncryptedSecretPayload_2.length());


                    //Payload Creation
                    //String Payload_2 = MP_IDs[0] + " " + PD2 + " " + EncryptedSecretPayload_2 + " " + Hashed_Nonce_R + " " + Current_time;
                    String Payload_2 =  PD2 + " " + EncryptedSecretPayload_2  + " " + Current_time;
                    System.out.println("Payload Size: "+Payload_2.length());
                    System.out.println("Signature : " + Signature_2);
                    System.out.println("Size of the Signature : " + Signature_2.length());

                    //String HMAC_2 = Hash(MP_IDs[0] + PD2 + M_CODE + r1 + r2 + N + n_r + S_ID + Current_time);
                    byte[] EncryptedPayloadBytes_2 = RSA_encrypt(Payload_2, publicKey_gNBr);
                    String EncryptedPayload_2 = Base64.getEncoder().encodeToString(EncryptedPayloadBytes_2);
                    System.out.println("Encrypted Payload 2 : " + EncryptedPayload_2);
                    String Message_2 = "TTP_SV_REP" + " " + MP_IDs[0] + " " + EncryptedPayload_2 + " " + Signature_2;
                    PET[loop_No][5] = System.nanoTime();

                    out.println(Message_2);

                    Sending_time = System.nanoTime();
                    TST[loop_No][2] = Sending_time;

                    System.out.println("Message 2 : " + Message_2);

                    //System.out.println("Hash length [bytes]: " + HMAC_2.getBytes().length);
                    System.out.println("Payload 2 length [bytes]: " + Payload_2.getBytes().length);
                    System.out.println("Message 2 length [bytes]: " + Message_2.getBytes().length);

                    System.out.println("Message 2 Sent at " + new Timestamp(Sending_time));

                    VerticalSpace();
                    ProtocolMsgCount = 2;

                }else if(input.startsWith("COMPLETE_D")){

                    System.out.println("%%%%%%%%%%%%%%%%%%%%%% MESSAGE 2 TO ROAMING gNB COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                    System.out.println(input);

                    VerticalSpace();
                    T_TTP_D = System.nanoTime();
                    System.out.println("Time taken for the conclusion of PROTOCOL SEGMENT D (T_D) [ms]: " + CheckTS(T_TTP_B, T_TTP_D));
                    System.out.println(TEXT_BLUE+"%%%%%%%%%%%%%%%%%%%%  PROTOCOL SEGMENT D COMPLETED    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"+TEXT_RESET);
                    exit = true;
                }else{
                    System.out.println(TEXT_PURPLE+"MESSAGE NOT RECOGNIZED.............==> DISCARDED"+TEXT_RESET);
                    VerticalSpace();
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // Clean up
            try {
                in.close();
                out.close();
                serverSocket.close();
                listener.close();
                System.out.println("gNBr Connection...Stopped");
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }
    }


    public void VerticalSpace(){

        System.out.println("\n\n");
    }

    //Function to get the current Time Stamp
    public static Timestamp getCurrentTimestamp(){
        return new Timestamp(System.currentTimeMillis());
    }

    public long CheckTS (long CheckingTS, long CurrentTS){

        return ((CurrentTS - CheckingTS)/1000000);
    }

    ///////////////////////////   ID / MIH Checking Functions //////////////////////////////////////////
    public boolean Check_ID(String Received_ID, String Checking_ID){

        return Checking_ID.matches(Received_ID);
    }

    public boolean Check_MIH(String Received_MIH, String Checking_MIH){

        return Checking_MIH.matches(Received_MIH);
    }

    public String MP_ID_ArrayGeneration(int ID_Range){

        String MP_ID_Array = RandomNonceGenerator();

        for(int x = 0 ; x < ID_Range ; x++){

            MP_ID_Array = MP_ID_Array+"SPACE"+RandomNonceGenerator();
        }

        //MP_IDs = MP_ID_Array.split("SPACE");

        return MP_ID_Array;
    }

    /////////////////////////////////   HASHING FUNCTIONS   //////////////////////////////////////

    public boolean CheckHash(String CheckingHash, String TargetHash){

        return CheckingHash.matches(TargetHash);
    }

    public static String Hash (String message) throws NoSuchAlgorithmException {
        // getInstance() method is called with algorithm SHA-512
        MessageDigest md = MessageDigest.getInstance("SHA-512");

        // digest() method is called
        // to calculate message digest of the input string
        // returned as array of byte
        byte[] messageDigest = md.digest(message.getBytes());

        // Convert byte array into signum representation
        BigInteger no = new BigInteger(1, messageDigest);

        // Convert message digest into hex value
        String hashtext = no.toString(16);

        // Add preceding 0s to make it 32 bit
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        // return the HashText
        return hashtext;
    }

    public static String Hash256 (String message) throws NoSuchAlgorithmException {
        // getInstance() method is called with algorithm SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // digest() method is called
        // to calculate message digest of the input string
        // returned as array of byte
        byte[] messageDigest = md.digest(message.getBytes());

        // Convert byte array into signum representation
        BigInteger no = new BigInteger(1, messageDigest);

        // Convert message digest into hex value
        String hashtext = no.toString(16);

        // Add preceding 0s to make it 32 bit
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        // return the HashText
        return hashtext;
    }

    public static String Hash128 (String message) throws NoSuchAlgorithmException {
        // getInstance() method is called with algorithm SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-1");

        // digest() method is called
        // to calculate message digest of the input string
        // returned as array of byte
        byte[] messageDigest = md.digest(message.getBytes());

        // Convert byte array into signum representation
        BigInteger no = new BigInteger(1, messageDigest);

        // Convert message digest into hex value
        String hashtext = no.toString(16);

        // Add preceding 0s to make it 32 bit
        while (hashtext.length() < 32) {
            hashtext = "0" + hashtext;
        }

        // return the HashText
        return hashtext;
    }

    public static String RandomNonceGenerator() {
        int leftLimit = 97; // letter 'a'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = 10;
        Random random = new Random();

        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        return generatedString;
    }

    /////////////////////////////////   DoS PUZZLE  /////////////////////////////////////////////

    public String DoS_Puzzle(int k_dos, String PublicKey,  String Client_ID, String Server_ID, String Client_Nonce, String Server_Nonce) throws UnknownHostException, Exception{

        long j = 0;

        String X;

        System.out.println("\n\nDoS PUZZLE STARTING...........");

        long ts_start = System.currentTimeMillis();

        while (true){

            X = RandomNonceGenerator();


            String BIhash = BIHash(PublicKey + Client_ID + Client_Nonce + Server_ID + Server_Nonce + X);

            if (CheckZeroCount(BIhash,k_dos)==true){
                System.out.println("SOLUTION FOUND....X = "+X);
                break;
            }

            j++;

        }

        long ts_end = System.currentTimeMillis();

        System.out.println("Number of Attempts :"+j);
        System.out.println("DoS Puzzle Process Time [ms]:"+(ts_end-ts_start));

        return X;

    }

    public void DoS_Puzzle_Verification(int k_dos, String PublicKey,  String Client_ID, String Server_ID, String Client_Nonce, String Server_Nonce, String X) throws UnknownHostException, Exception{

        String VerifyingHash = BIHash(PublicKey + Client_ID + Client_Nonce + Server_ID + Server_Nonce + X);

        System.out.println("Received X : " + X);
        System.out.println("Verifying Hash : " + VerifyingHash);

        if (CheckZeroCount(VerifyingHash,k_dos)){
            System.out.println(TEXT_GREEN+".................The DoS Puzzle is VERIFIED..............\n\n"+TEXT_RESET);
            PuzzleVerified = true;
        }else {

            System.out.println(TEXT_RED+".............The DoS Puzzle is Not Verified ==> DoS Attack Detected..........\n\n"+TEXT_RESET);
        }


    }

    ////////////////////////////    Migration Key Parameter Generation Function  ////////////////////////////////////////////////

    public void Migration_Key__Parameter_Generation(int bit_length){

        int x = 0;

        long ts_start = System.currentTimeMillis();

        SecureRandom s = new SecureRandom();
        N = new BigInteger(bit_length,100,s);

        while(x==0){
            r1 = new BigInteger(bit_length,100,s);
            r1_dash = r1.mod(N);
            if((r1_dash.compareTo(N.divide(new BigInteger("100"))) < 0 )){
                x=1;
            }
        }

        System.out.println("N : "+N);
        System.out.println("r1 : "+r1);
        System.out.println("r1' : "+r1_dash);

        x=0;
        while(x==0){
            r2 = new BigInteger(bit_length,100,s);
            r2_dash = r2.mod(N);
            if((r1_dash.multiply(r2_dash)).compareTo(N) < 0){
                x=1;
            }
        }

        System.out.println("r2 : "+r2);
        System.out.println("r2' : "+r2_dash);

        long ts_end = System.currentTimeMillis();
        System.out.println("Migraton Key Parameter Generation Process Time [ms]:"+(ts_end-ts_start));

        System.out.println("r1' x r2' = "+r1_dash.multiply(r2_dash).toString());
        System.out.println("r1 x r2 mod N = "+r1.multiply(r2).mod(N).toString());


    }



    /////////////////////////// RSA /////////////////////////////////////////////
    public static void RSA_generate_keys (String Certificate_Path, String Entity_Name) throws NoSuchAlgorithmException, IOException{

        // Get an instance of the RSA key generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(RSA_Key_length);

        // Generate the KeyPair
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Get the public and private key
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        System.out.println("Entity Name : "+Entity_Name);

        System.out.println("RSA Private Key : "+privateKey);
        System.out.println("RSA Public Key : "+publicKey);

        //Creating the Files for storing the Private and Public Keys

        File privateKeyFile = new File(Certificate_Path+"PRIVATE_KEY_"+Entity_Name+".txt");
        privateKeyFile.createNewFile();

        File publicKeyFile = new File(Certificate_Path+"PUBLIC_KEY_"+Entity_Name+".txt");
        publicKeyFile.createNewFile();

        byte[] encodedPublicKey = publicKey.getEncoded();
        String b64PublicKey = Base64.getEncoder().encodeToString(encodedPublicKey);

        byte[] encodedPrivateKey = privateKey.getEncoded();
        String b64PrivateKey = Base64.getEncoder().encodeToString(encodedPrivateKey);

        //Writing the Keys to the created files
        try (OutputStreamWriter publicKeyWriter =
                     new OutputStreamWriter(
                             new FileOutputStream(publicKeyFile),
                             StandardCharsets.US_ASCII.newEncoder())) {
            publicKeyWriter.write(b64PublicKey);
        }

        try (OutputStreamWriter privateKeyWriter =
                     new OutputStreamWriter(
                             new FileOutputStream(privateKeyFile),
                             StandardCharsets.US_ASCII.newEncoder())) {
            privateKeyWriter.write(b64PrivateKey);
        }

        System.out.println("Certificate is generated of the Entity "+Entity_Name+" at"+getCurrentTimestamp()+"\n\n");

    }

    public void RSA_load_own_keys(String Certificate_Path, String Entity_Name) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        KeyFactory kf = KeyFactory.getInstance("RSA");

        String stringPrivateKey = new String(Files.readAllBytes(Paths.get(Certificate_Path+"PRIVATE_KEY_"+Entity_Name+".txt")));

        System.out.println("Loaded String Private Key : "+stringPrivateKey);

        byte[] decodedPrivateKey = Base64.getDecoder().decode(stringPrivateKey);

        //System.out.println("Decoded Private Key : "+decodedPrivateKey);

        KeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decodedPrivateKey);

        //System.out.println("Key Specification of Private Key : "+keySpecPrivate);

        PrivateKey privateKey = kf.generatePrivate(keySpecPrivate);

        privateKey_TTP = privateKey;

        String stringPublicKey = new String(Files.readAllBytes(Paths.get(Certificate_Path+"PUBLIC_KEY_"+Entity_Name+".txt")));

        System.out.println("Loaded String Public Key : "+stringPublicKey);

        byte[] decodedPublicKey = Base64.getDecoder().decode(stringPublicKey);

        KeySpec keySpecPublic = new X509EncodedKeySpec(decodedPublicKey);

        PublicKey publicKey = kf.generatePublic(keySpecPublic);

        publicKey_TTP = publicKey;

        System.out.println("Entity Name : "+Entity_Name);
        System.out.println("Loaded RSA Private Key : "+privateKey);
        System.out.println("Loaded RSA Public Key : "+publicKey);

    }

    public PublicKey RSA_load_Signing_key (String Certificate_Path, String Entity_Name) throws  NoSuchAlgorithmException, Exception{

        KeyFactory kf = KeyFactory.getInstance("RSA");

        String stringSigningKey = new String(Files.readAllBytes(Paths.get(Certificate_Path+"PRIVATE_KEY_"+Entity_Name+".txt")));

        System.out.println("Loaded String Signing Key : "+stringSigningKey);

        byte[] decodedSigningKey = Base64.getDecoder().decode(stringSigningKey);

        //System.out.println("Decoded Private Key : "+decodedPrivateKey);

        KeySpec keySpecSigning = new X509EncodedKeySpec(decodedSigningKey);

        //System.out.println("Key Specification of Private Key : "+keySpecPrivate);

        PublicKey signingKey = kf.generatePublic(keySpecSigning);

        return signingKey;

    }

    public PrivateKey RSA_load_Verifying_key (String Certificate_Path, String Entity_Name) throws  NoSuchAlgorithmException, Exception{

        KeyFactory kf = KeyFactory.getInstance("RSA");

        String stringVerifyingKey = new String(Files.readAllBytes(Paths.get(Certificate_Path+"PUBLIC_KEY_"+Entity_Name+".txt")));

        System.out.println("Loaded String Verifying Key : "+stringVerifyingKey);

        byte[] decodedVerifyingKey = Base64.getDecoder().decode(stringVerifyingKey);

        //System.out.println("Decoded Private Key : "+decodedPrivateKey);

        KeySpec keySpecVerifying = new PKCS8EncodedKeySpec(decodedVerifyingKey);

        //System.out.println("Key Specification of Private Key : "+keySpecPrivate);

        PrivateKey verifyingKey = kf.generatePrivate(keySpecVerifying);

        return verifyingKey;
    }

    public PublicKey RSA_load_public_key(String Certificate_Path, String Entity_Name) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {

        KeyFactory kf = KeyFactory.getInstance("RSA");

        String stringPublicKey = new String(Files.readAllBytes(Paths.get(Certificate_Path+"PUBLIC_KEY_"+Entity_Name+".txt")));

        System.out.println("Loaded String Public Key : "+stringPublicKey);

        byte[] decodedPublicKey = Base64.getDecoder().decode(stringPublicKey);

        KeySpec keySpecPublic = new X509EncodedKeySpec(decodedPublicKey);

        PublicKey publicKey = kf.generatePublic(keySpecPublic);

        System.out.println("Entity Name : "+Entity_Name);
        System.out.println("Loaded RSA Public Key : "+publicKey);

        return publicKey;

    }

    public static byte[] RSA_encrypt (String plainText, PublicKey publicKey ) throws Exception
    {
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");
        //Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");

        //Initializing the Cipher only with the RSA without any padding or a BLock Cipher Mode
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //Perform Encryption
        //byte[] cipherTextArray = cipher.doFinal(plainText.getBytes()) ;

        byte[] plainTextArray = null;

        try {
            plainTextArray = plainText.getBytes();
        } catch(ArrayIndexOutOfBoundsException e) {
            System.out.println(e);
        }

        byte[] cipherText = cipher.doFinal(plainTextArray) ;

        return cipherText;

        //return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    public static String RSA_sign (String plainText, PrivateKey privateKey) throws Exception
    {

        System.out.println("Private Key for Signing : "+privateKey);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(plainText.getBytes());

        byte[] signatureBytes = signature.sign();

        return Base64.getEncoder().encodeToString(signatureBytes);

    }

    public static String RSA_decrypt (String cipherText, PrivateKey privateKey) throws Exception
    {
        byte[] cipherTextArray = Base64.getDecoder().decode(cipherText);
        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");
        //Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");

        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        //Perform Decryption
        return new String(cipher.doFinal(cipherTextArray));
    }

    public static boolean RSA_verify (String VerifyingSignature, String signatureString, PublicKey publicKey ) throws Exception
    {

        Signature signature = Signature.getInstance("SHA256withRSA");

        signature.initVerify(publicKey);
        signature.update(VerifyingSignature.getBytes());

        byte[] signatureBytes = Base64.getDecoder().decode(signatureString);

        return signature.verify(signatureBytes);

    }

    public static String BIHash (String message) throws NoSuchAlgorithmException {

        String HashAlgorithm = "SHA-512";

        // getInstance() method is called with algorithm SHA-512
        MessageDigest md = MessageDigest.getInstance(HashAlgorithm);

        int k = 155;
        // digest() method is called
        // to calculate message digest of the input string
        // returned as array of byte
        byte[] messageDigest = md.digest(message.getBytes());

        // Convert byte array into signum representation
        BigInteger no = new BigInteger(1, messageDigest);

        int BIlength = no.toString().length();

        //System.out.println("BI Length = "+BIlength);

        String hash = no.toString();

        if( BIlength < k ){
            for(int i=0; i < (k-BIlength); i++){
                hash = "0"+hash;
            }
        }

        //System.out.println("Modified Hash : "+hash);
        //System.out.println("Modified Hash Length: "+hash.length());

        return  hash;
    }

    public static Boolean CheckZeroCount(String hash, int k_dos){

        char[] hashArray = hash.toCharArray();
        Boolean Check = false;

        for(int i=0; i < k_dos ; i++){


            if (hashArray[i] == '0'){
                Check = true;
            }else {
                Check = false;
                break;
            }
        }
        return Check;

    }

    //@@@@@@@@@@@@@@@@@ Advanced Encryption Standard    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

    public static String AES_Encrypt(String strToEncrypt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, AES_Key_Length);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
            return Base64.getEncoder()
                    .encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String AES_Decrypt(String strToDecrypt) {
        try {
            byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), SALT.getBytes(), 65536, AES_Key_Length);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKeySpec secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    //@@@@@@@@@@@@@@@@@@@@@@@@@ Elliptic Curve Cryptography @@@@@@@@@@@@@@@@@@@@@@@@@@@

    public static String Generate_ECDH_SharingKey_B(int Key_Size)throws NoSuchAlgorithmException{
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(Key_Size);
        kpB = kpg.generateKeyPair();
        byte[] SharingKey = kpB.getPublic().getEncoded();

        String SK = encodeHexString(SharingKey);
        System.out.println("Sharing Key: "+SK);
        System.out.println("Sharing Key Size : "+SK.length());
        return SK;
    }

    public static String Generate_ECDH_SharingKey_C(int Key_Size)throws NoSuchAlgorithmException{
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(Key_Size);
        kpC1 = kpg.generateKeyPair();
        byte[] SharingKey = kpC1.getPublic().getEncoded();

        String SK = encodeHexString(SharingKey);
        System.out.println("Sharing Key: "+SK);
        System.out.println("Sharing Key Size : "+SK.length());
        return SK;
    }

    public static String Generate_ECDH_SharingKey_D(int Key_Size)throws NoSuchAlgorithmException{
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(Key_Size);
        kpD = kpg.generateKeyPair();
        byte[] SharingKey = kpD.getPublic().getEncoded();

        String SK = encodeHexString(SharingKey);
        System.out.println("Sharing Key: "+SK);
        System.out.println("Sharing Key Size : "+SK.length());
        return SK;
    }

    public static String Create_ECDH_SecretKey(String StringSharedKey, String StringSharingKey, KeyPair kp) throws NoSuchAlgorithmException, InvalidKeySpecException,InvalidKeyException {

        byte[] SharedKey = decodeHexString(StringSharedKey);
        byte[] SharingKey = decodeHexString(StringSharingKey);

        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(SharedKey);
        PublicKey SK = kf.generatePublic(pkSpec);

        // Perform key agreement
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(SK, true);

        // Read shared secret
        byte[] sharedSecret = ka.generateSecret();
        System.out.println("Shared secret: "+ encodeHexString(sharedSecret));

        // Derive a key from the shared secret and both public keys
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(sharedSecret);
        // Simple deterministic ordering
        List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(SharingKey), ByteBuffer.wrap(SharedKey));
        Collections.sort(keys);
        hash.update(keys.get(0));
        hash.update(keys.get(1));

        byte[] derivedKey = hash.digest();
        String FinalKey = encodeHexString(derivedKey);
        System.out.println("Final key: "+ FinalKey);

        return FinalKey;
    }


    public static String encodeHexString(byte[] byteArray) {
        StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }

    public static String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    public static byte[] decodeHexString(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException(
                    "Invalid hexadecimal String supplied.");
        }

        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }

    public static byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }

    private static int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if(digit == -1) {
            throw new IllegalArgumentException(
                    "Invalid Hexadecimal Character: "+ hexChar);
        }
        return digit;
    }




}
