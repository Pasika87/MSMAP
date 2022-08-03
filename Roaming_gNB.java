/**
 * Program Name : Security Protocol for MEC Service Migration Roaming gNB
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


public class Roaming_gNB {


    public static int R_PORT = 2000;         //gNBr Running Port
    public static int TTP_M_PORT = 1500;       //TTP Migration Port created for the gNBr communication
    public static int S_PORT = 900;
    public static int S1_PORT = 9000;
    public static int S2_PORT = 9500;
    public static int S3_PORT = 9700;
    static int OSS_MVR_PORT = 10000;

    public String S_ID;
    public String R_ID = "10.0.0.3";
    public String MVR_ID = "192.168.10.2";
    public String TTP_ID;

    public static long Start_time;
    public static long End_time;
    public static long Process_time;
    public static long Received_time;
    public static long Sending_time;
    public static long Current_time;
    public static long Entity_Start_time;
    public static long Entity_End_time;
    public static long T_R_C;
    public static long T_R_D;
    public static long T_R_E;
    public static long T_R_F;
    public static long ClockSkew = 5000;    //Defined Clock Skew : 5 seconds
    public static long Delta_TS;
    public static long ReceivedTS;

    public static String encryptedString;

    public String[] MP_IDs;
    public String MP_ID;

    public static String Plaintext;
    public static int RSA_Key_length = 4096; //bits
    public static int AES_Key_Length = 256; //bits
    public static int ECDH_Key_Length_1 = 256; //bits
    public static int ECDH_Key_Length_2 = 128; //bits
    public static int ECDH_Key_Length_3 = 112; //bits

    public final String K_dos_TTP = "4";

    public PublicKey publicKey_OSS_CA, publicKey_gNBs, publicKey_gNBr, publicKey_OSS_MVR, publicKey_TTP;

    public PrivateKey privateKey_gNBr, verifyingKey_gNBr;

    public static String Common_RSA_Certificate_Path = "E:/OneDrive/PhD Ireland/PhD Work/MEC/Research Directions/Service Migration Prediction/Implementation/MECMigrationProtocol/out/production/MECMigrationProtocol/";

    public static String Entity_gNBs = "gNBs", Entity_gNBr = "gNBr", Entity_OSS_CA = "OSS_CA", Entity_OSS_MVR = "OSS_MVR", Entity_TTP = "TTP";

    public static String RSA_Private_Key_File_Name, RSA_Public_Key_File_Name;

    //AES Variables
    public static SecretKeySpec AES_secretKey;
    public static byte[] AES_key;
    public static byte[] iv;

    //ECDH VAriables

    public static KeyPair kpC2, kpD, kpE1, kpF;
    public static String PC1, PD1, PD2, PC3, PE1, PF1, PF2;

    //Secret Key and Salt for the AESEncrypt() and AESDecrypt() Functions
    public static String SECRET_KEY;
    public static final String SALT = "ssshhhhhhhhhhh!!!!";

    private ServerSocket listener;

    public InetAddress S_IP_Address;

    public InetAddress MVR_IP_Address;

    public InetAddress TTP_IP_Address;

    public String n_s;
    public String n_r;
    public String n_r_key;
    public String MIH;

    public BigInteger r1, r2, N;
    public static String K_M;

    public static String M_CODE, MES_ID, MES_STATE, MES_DATA, MES_REQ;
    public static boolean MES_VER = true;
    public static String MES_CODE;
    public static boolean MES_RES = true;

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

    public ArrayList<String>[][] SecurityProfile;

    public static int N_Messages = 9;
    public static int N_Trials = 22;

    public static Long[] EST; //Entity Start Time
    public static Long[][] PET; //Process End Time ==> Indicating the end time of each processed message prior to transmission
    public static Long[][] TST; //Transmission Start Time ==> Indicating the starting time at the sender end
    public static Long[][] TET; //Transmission End Time ==> Indicating the received time time at the receiver end
    public static Long[] EET; //Entity End Time

    public int loop_No = 0;

    public Roaming_gNB() throws IOException,NoSuchAlgorithmException,InvalidKeySpecException,Exception {

        //Loading the RSA keys of this Entity
        RSA_load_own_keys(Common_RSA_Certificate_Path,Entity_gNBr);



        System.out.println("\n\n RSA KEY LOADING IS CONCLUDED.........%%%%%%%%%%%%%%%%%% \n\n");

        //verifyingKey_gNBs = RSA_load_Verifying_key(Common_RSA_Certificate_Path,Entity_gNBs);

        //Creation of the ServerSocket
        //ServerSocket serverSocket = new ServerSocket(R_PORT);

        TTP_IP_Address = InetAddress.getLocalHost();
/*
        TTP_IP_Address = InetAddress.getByAddress(new byte[] {
                (byte)193, (byte)1, (byte)132, (byte)81}
        );*/

        System.out.println("Roaming gNB Running IP Address : "+TTP_IP_Address);

        EST = new Long[N_Trials];
        PET = new Long[N_Trials][N_Messages];
        TST = new Long[N_Trials][N_Messages];
        TET = new Long[N_Trials][N_Messages];
        EET = new Long[N_Trials];


        while(true) {


            System.out.println(TEXT_BLUE+"%%%%%%%%%%%%%%%%%         The Roaming gNB is OPERATING      %%%%%%%%%%%%%%%%%%%%");
            System.out.println("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"+TEXT_RESET);
            VerticalSpace();

            SecurityProfile = new ArrayList[3][5];

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%   Message 1 FROM gNBs  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            //Function for Listening to Message 1
            startListening(R_PORT);

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%   Messages TO TTP SERVER %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            Socket TTP_socket = new Socket(TTP_IP_Address, TTP_M_PORT);

            BufferedReader in = new BufferedReader(new InputStreamReader(TTP_socket.getInputStream()));
            PrintWriter out = new PrintWriter(TTP_socket.getOutputStream(), true);

            publicKey_TTP = RSA_load_public_key(Common_RSA_Certificate_Path, Entity_TTP);

            SignatureFailCount = 0;
            NonceVerifierCount = 0;
            ProtocolMsgCount = 0;
            exit = false;

            while (exit == false) {


                if (ProtocolMsgCount % 2 != 0) {

                    input = in.readLine();
                }

                //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 1  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                if ((ProtocolMsgCount == 0) || (input.startsWith("RETRANSMIT_D0"))) {

                    n_r = RandomNonceGenerator();
                    System.out.println("Generated R Nonce for gNBs [Nr] :" + n_r);

                    PD1 = Generate_ECDH_SharingKey_D(ECDH_Key_Length_3);

                    Current_time = System.nanoTime();
                    String TTP_Pre_Signature_1 = Hash(TTP_ID + " " + Current_time);
                    String TTP_Signature_1 = RSA_sign(TTP_Pre_Signature_1, privateKey_gNBr);

                    String TTP_Payload_1 = TTP_ID + " " + MP_ID + " " + n_r + " " + PC1 + " " + PD1 + " " + Current_time;
                    System.out.println("Signature : " + TTP_Signature_1);
                    System.out.println("Size of the Signature : " + TTP_Signature_1.length());
                    System.out.println("Size of the Payload : "+TTP_Payload_1.length());
                    System.out.println("Size of the PC1 : "+PC1.length());
                    System.out.println("Size of the PD1 : "+PD1.length());
                    System.out.println("TTP ID Length : "+TTP_ID.length());

                    String TTP_HMAC_1 = Hash(TTP_ID + MP_ID + n_r + PC1 + PD1 + Current_time);
                    byte[] TTP_EncryptedPayloadBytes_1 = RSA_encrypt(TTP_Payload_1, publicKey_TTP);
                    String TTP_EncryptedPayload_1 = Base64.getEncoder().encodeToString(TTP_EncryptedPayloadBytes_1);
                    System.out.println("Encrypted Payload 1 : " + TTP_EncryptedPayload_1);
                    String TTP_Message_1 = "R_SV_REQ" + " " + R_ID + " " + TTP_EncryptedPayload_1 + " " + TTP_Signature_1 + " " + TTP_HMAC_1;
                    PET[loop_No][1] = System.nanoTime();

                    out.println(TTP_Message_1);

                    Sending_time = System.nanoTime();
                    TST[loop_No][0] = Sending_time;
                    System.out.println("Message 1 : " + TTP_Message_1);
                    System.out.println("Hash length [bytes]: " + TTP_HMAC_1.getBytes().length);
                    System.out.println("Payload 1 length [bytes]: " + TTP_Payload_1.getBytes().length);
                    System.out.println("Message 1 length [bytes]: " + TTP_Message_1.getBytes().length);
                    System.out.println("Message 1 to TTP Sent at " + new Timestamp(Sending_time));

                    ProtocolMsgCount = 1;
                    VerticalSpace();

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%   Message 3 FROM TTP SERVER %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                } else if (ProtocolMsgCount == 1) {

                    Received_time = System.nanoTime();
                    TET[loop_No][1] = Received_time;
                    System.out.println("Message 3 from TTP: " + input + " received at.." + new Timestamp(Received_time));
                    String Message_3[] = input.split(" ");
                    MIH = Message_3[0];

                    if (Check_MIH(MIH, "TTP_SV_REP")) {
                        System.out.println(TEXT_GREEN + "The Received MIH matches....." + TEXT_RESET);

                        String EncryptedPayload_3 = Message_3[2];
                        String stringSignature_3 = Message_3[3];
                        System.out.println("Encrypted Payload : " + EncryptedPayload_3);
                        String DecryptedPayload_3 = RSA_decrypt(EncryptedPayload_3, privateKey_gNBr);
                        System.out.println("Decrypted Payload : " + DecryptedPayload_3);
                        String[] DecryptedPayloadArray_3 = DecryptedPayload_3.split(" ");

                        ReceivedTS = new Long(DecryptedPayloadArray_3[2]);
                        Delta_TS = CheckTS(ReceivedTS, Received_time);
                        System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                        if (Delta_TS <= ClockSkew) {
                            System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);
                            String VerifyingSignature_3 = Hash(S_ID + ReceivedTS);

                            if (RSA_verify(VerifyingSignature_3, stringSignature_3, publicKey_TTP)) {
                                System.out.println(TEXT_GREEN + "Signatures are Matching..............." + TEXT_RESET);

                                MP_ID = Message_3[1];
                                PD2 = DecryptedPayloadArray_3[0];

                                SECRET_KEY = Create_ECDH_SecretKey(PD2,PD1,kpD);

                                String DecryptedSecretPayload_3 = AES_Decrypt(DecryptedPayloadArray_3[1]);
                                String[] DecryptedSecretPayloadArray_3 = DecryptedSecretPayload_3.split(" ");

                                String NonceVerifier_TTP = DecryptedSecretPayloadArray_3[4];

                                if (NonceVerifier_TTP.equals(Hash128(n_r + ReceivedTS))) {
                                    System.out.println(TEXT_GREEN + "TTP Nonce is Verified..............." + TEXT_RESET);

                                    M_CODE = DecryptedSecretPayloadArray_3[0];
                                    r1 = new BigInteger(DecryptedSecretPayloadArray_3[1]);
                                    r2 = new BigInteger(DecryptedSecretPayloadArray_3[2]);
                                    N = new BigInteger(DecryptedSecretPayloadArray_3[3]);
                                    System.out.println("M CODE  : " + M_CODE);

                                    VerticalSpace();
                                    System.out.println("%%%%%%%%%%%%%%%%%%%%%% MESSAGE 2 FROM TTP SERVER COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");

                                    out.println("COMPLETE_D");
                                    System.out.println(TEXT_BLUE + "%%%%%%%%%%%%%%%%%%%%%% PROTOCOL SEGMENT D COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n" + TEXT_RESET);
                                    VerticalSpace();
                                    T_R_D = System.nanoTime();
                                    PET[loop_No][2] = T_R_D;
                                    System.out.println("Time taken for the conclusion of PROTOCOL SEGMENT D (T_D) [ms]: " + CheckTS(Entity_Start_time, T_R_D));
                                    exit = true;
                                    VerticalSpace();

                                } else {
                                    System.out.println(TEXT_RED + "TTP Nonce is NOT Verified..............." + TEXT_RESET);
                                    System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                                    out.println("RETRANSMIT_D1");
                                    NonceVerifierCount++;
                                    if (NonceVerifierCount == 3) exit(0);
                                }
                            } else {
                                System.out.println(TEXT_RED + "Signatures Does not match..............." + TEXT_RESET);
                                System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED..............." + TEXT_RESET);

                                out.println("RETRANSMIT_D1");
                                SignatureFailCount++;
                                if (SignatureFailCount == 3) exit(0);
                            }
                        } else {

                            System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                            System.out.println(TEXT_RED + "DISCARD MESSAGE................." + TEXT_RESET);
                        }
                    } else {
                        System.out.println(TEXT_RED + "The Received MIH DOES NOT match....." + TEXT_RESET);
                    }
                } else {
                    System.out.println(TEXT_PURPLE + "MESSAGE NOT RECOGNIZED.............==> DISCARDED" + TEXT_RESET);
                    VerticalSpace();
                }
            }
            in.close();
            out.close();
            TTP_socket.close();

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   MESSAGE TO Source gNB  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            S_IP_Address = InetAddress.getLocalHost();

            Socket S_socket = new Socket(S_IP_Address, 9000);

            //BufferedReader in = new BufferedReader(new InputStreamReader(TTP_socket.getInputStream()));
            //PrintWriter out = new PrintWriter(new OutputStreamWriter(TTP_socket.getOutputStream()));

            in = new BufferedReader(new InputStreamReader(S_socket.getInputStream()));
            out = new PrintWriter(S_socket.getOutputStream(), true);

            SignatureFailCount = 0;
            NonceVerifierCount = 0;
            ProtocolMsgCount = 0;
            exit = false;

            while (exit == false) {

                if (ProtocolMsgCount % 2 != 0) {
                    input = in.readLine();
                }

                if ((ProtocolMsgCount == 0) || (input.startsWith("RETRANSMIT_C1"))) {
                    n_r_key = RandomNonceGenerator();
                    System.out.println("Nr2 : "+n_r_key);

                    PC3 = Generate_ECDH_SharingKey_C2(ECDH_Key_Length_3);
                    SECRET_KEY = Create_ECDH_SecretKey(PC1,PC3,kpC2);

                    Current_time = System.nanoTime();
                    String S_SecretPayload_1 = M_CODE+ " " +n_r_key;
                    String S_EncryptedSecretPayload_1 = AES_Encrypt(S_SecretPayload_1);
                    System.out.println("Secret Payload Size :"+S_EncryptedSecretPayload_1.length());

                    String S_Pre_Signature_1 = Hash(S_ID + " " + Current_time);
                    String S_Signature_1 = RSA_sign(S_Pre_Signature_1, privateKey_gNBr);
                    String S_Payload_1 = R_ID + " " + MP_ID + " " + PC3 + " " + S_EncryptedSecretPayload_1 + " " + Hash128(n_s + Current_time) + " " + Current_time;
                    System.out.println("Signature : " + S_Signature_1);
                    System.out.println("Size of the Signature : " + S_Signature_1.length());

                    //String S_HMAC_1 = Hash(R_ID + MP_ID + M_CODE + n_r_key + n_s + S_ID + Current_time);
                    byte[] S_EncryptedPayloadBytes_1 = RSA_encrypt(S_Payload_1, publicKey_gNBs);
                    String S_EncryptedPayload_1 = Base64.getEncoder().encodeToString(S_EncryptedPayloadBytes_1);
                    System.out.println("Encrypted Payload 1 : " + S_EncryptedPayload_1);
                    String S_Message_1 = "R_MA_REP" + " " + S_EncryptedPayload_1 + " " + S_Signature_1;
                    PET[loop_No][3] = System.nanoTime();

                    out.println(S_Message_1);

                    Sending_time = System.nanoTime();
                    TST[loop_No][1] = Sending_time;
                    System.out.println("Message 1 : " + S_Message_1);
                    //System.out.println("Hash length [bytes]: " + S_HMAC_1.getBytes().length);
                    System.out.println("Payload 1 length [bytes]: " + S_Payload_1.getBytes().length);
                    System.out.println("Message 1 length [bytes]: " + S_Message_1.getBytes().length);
                    System.out.println("Message 1 to gNBs Sent at " + new Timestamp(Sending_time));

                    VerticalSpace();
                    ProtocolMsgCount = 1;
                    T_R_C = System.nanoTime();
                    System.out.println("Time taken for the conclusion of PROTOCOL SEGMENT C (T_C) [ms]: " + CheckTS(T_R_D, T_R_C));
                    VerticalSpace();

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  MESSAGE 2 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
                } else if (ProtocolMsgCount == 1) {

                    Received_time = System.nanoTime();
                    TET[loop_No][2] = Received_time;
                    System.out.println("Message 2 from gNBs: " + input + " received at.." + new Timestamp(Received_time));
                    String Message_2[] = input.split(" ");
                    MIH = Message_2[0];

                    String EncryptedPayload_2 = Message_2[1];
                    System.out.println("Encrypted Payload : " + EncryptedPayload_2);
                    String DecryptedPayload_2 = RSA_decrypt(EncryptedPayload_2, privateKey_gNBr);
                    System.out.println("Decrypted Payload : " + DecryptedPayload_2);
                    String[] DecryptedPayloadArray_2 = DecryptedPayload_2.split(" ");

                    ReceivedTS = new Long(DecryptedPayloadArray_2[7]);
                    Delta_TS = CheckTS(ReceivedTS, Received_time);
                    System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                    if (Delta_TS <= ClockSkew) {
                        System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);

                        if (Check_MIH(MIH, "S_MES_REQ")) {
                            System.out.println(TEXT_GREEN + "The Received MIH matches....." + TEXT_RESET);

                            String Received_MPID = DecryptedPayloadArray_2[0];
                            MES_ID = DecryptedPayloadArray_2[1];
                            MES_STATE = DecryptedPayloadArray_2[2];
                            MES_DATA = DecryptedPayloadArray_2[3];
                            MES_REQ = DecryptedPayloadArray_2[4];
                            MVR_ID = DecryptedPayloadArray_2[5];
                            PE1 = DecryptedPayloadArray_2[6];

                            String HMAC_2 = Hash(MP_ID + MES_ID + MES_STATE + MES_DATA + MES_REQ + MVR_ID + PE1 + ReceivedTS);
                            System.out.println("Received HMAC 3: " + Message_2[2]);
                            System.out.println("Formed HMAC 3: " + HMAC_2);

                            if (CheckHash(Message_2[2], HMAC_2)) {
                                System.out.println(TEXT_GREEN + "The Hashed MACs are MATCHING ==> INTEGRITY SECURED.............." + TEXT_RESET);

                                if (Received_MPID.equals(MP_ID)) {
                                    System.out.println(TEXT_GREEN + "The MP_ID is VERIFIED.............." + TEXT_RESET);
                                    System.out.println("MP_ID : " + MP_ID);
                                    System.out.println("MES_ID : " + MES_ID);
                                    System.out.println("MES_STATE : " + MES_STATE);
                                    System.out.println("MES_DATA : " + MES_DATA);
                                    System.out.println("MES_REQ : " + MES_REQ);
                                    System.out.println("MVR ID : " + MVR_ID);
                                    System.out.println("Received PE2 : " + PE1);

                                    System.out.println("%%%%%%%%%%%%%%%%%%%%%% MESSAGE 2 FROM gNodeB S COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                                    PET[loop_No][4] = System.nanoTime();
                                    ProtocolMsgCount = 2;
                                    VerticalSpace();

                                } else
                                    System.out.println(TEXT_RED + "The MP_ID NOT Verified.............." + TEXT_RESET);
                            } else {
                                System.out.println(TEXT_RED + "The Hashed MACs are NOT MATCHING ==> INTEGRITY VIOLATED.............." + TEXT_RESET);
                                System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                                out.println("RETRANSMIT_E0");
                            }
                        } else {
                            System.out.println(TEXT_RED + "The Received MIH DOES NOT match....." + TEXT_RESET);
                        }
                    } else {
                        System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                        System.out.println(TEXT_RED + "MESSAGE DISCARDED................." + TEXT_RESET);
                        exit(0);
                    }
                } else if (ProtocolMsgCount == 2) {
                    out.println("ACK_E0");
                    exit = true;

                } else {
                    System.out.println(TEXT_PURPLE + "MESSAGE NOT RECOGNIZED.............==> DISCARDED" + TEXT_RESET);
                    VerticalSpace();
                }
            }

            in.close();
            out.close();
            S_socket.close();


            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% MVR COMMUNICATION  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            publicKey_OSS_MVR = RSA_load_public_key(Common_RSA_Certificate_Path, Entity_OSS_MVR);

            n_r = RandomNonceGenerator();

            MVR_IP_Address = InetAddress.getLocalHost();

            Socket MVR_socket = new Socket(MVR_IP_Address, OSS_MVR_PORT);

            in = new BufferedReader(new InputStreamReader(MVR_socket.getInputStream()));
            out = new PrintWriter(MVR_socket.getOutputStream(), true);

            SignatureFailCount = 0;
            NonceVerifierCount = 0;
            ProtocolMsgCount = 0;
            exit = false;

            while (exit == false) {

                if (ProtocolMsgCount % 2 != 0) {
                    input = in.readLine();
                }

                if ((ProtocolMsgCount == 0) || (input.startsWith("RETRANSMIT_F0"))) {
                    PF1 = Generate_ECDH_SharingKey_F(ECDH_Key_Length_3);

                    Current_time = System.nanoTime();
                    String MVR_Pre_Signature_1 = Hash(MVR_ID + " " + Current_time);
                    String MVR_Signature_1 = RSA_sign(MVR_Pre_Signature_1, privateKey_gNBr);

                    String MVR_Payload_1 = MES_ID + " " + MES_STATE + " " + S_ID + " " + R_ID + " " + n_r + " " + PE1 + " " + PF1 + " " + Current_time;
                    System.out.println("Size of the Payload : "+MVR_Payload_1.length());

                    System.out.println("Signature : " + MVR_Signature_1);
                    System.out.println("Size of the Signature : " + MVR_Signature_1.length());
                    String MVR_HMAC_1 = Hash(MES_ID + MES_STATE + S_ID + R_ID + n_r + PE1 + PF1 + Current_time);
                    byte[] MVR_EncryptedPayloadBytes_1 = RSA_encrypt(MVR_Payload_1, publicKey_OSS_MVR);
                    String MVR_EncryptedPayload_1 = Base64.getEncoder().encodeToString(MVR_EncryptedPayloadBytes_1);
                    System.out.println("Encrypted Payload 1 : " + MVR_EncryptedPayload_1);
                    String MVR_Message_1 = "R_MES_REP" + " " + MVR_EncryptedPayload_1 + " " + MVR_Signature_1 + " " + MVR_HMAC_1;
                    PET[loop_No][5] = System.nanoTime();

                    out.println(MVR_Message_1);

                    Sending_time = System.nanoTime();
                    TST[loop_No][2] = Sending_time;
                    System.out.println("Message 1 : " + MVR_Message_1);
                    System.out.println("Hash length [bytes]: " + MVR_HMAC_1.getBytes().length);
                    System.out.println("Payload 1 length [bytes]: " + MVR_Payload_1.getBytes().length);
                    System.out.println("Message 1 length [bytes]: " + MVR_Message_1.getBytes().length);
                    System.out.println("Message 1 to MVR Sent at " + new Timestamp(Sending_time));

                    ProtocolMsgCount = 1;

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  MESSAGE 2  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                } else if (ProtocolMsgCount == 1) {

                    VerticalSpace();
                    Received_time = System.nanoTime();
                    TET[loop_No][3] = Received_time;
                    System.out.println("Message 2 from MVR: " + input + " received at.." + new Timestamp(System.currentTimeMillis()));
                    String MVR_Message_2[] = input.split(" ");
                    String EncryptedPayload_1 = MVR_Message_2[1];
                    String stringSignature_1 = MVR_Message_2[2];
                    System.out.println("Encrypted Payload : " + EncryptedPayload_1);
                    String DecryptedPayload_1 = RSA_decrypt(EncryptedPayload_1, privateKey_gNBr);
                    System.out.println("Decrypted Payload : " + DecryptedPayload_1);
                    String[] DecryptedPayloadArray_1 = DecryptedPayload_1.split(" ");

                    ReceivedTS = new Long(DecryptedPayloadArray_1[4]);
                    Delta_TS = CheckTS(ReceivedTS, Received_time);
                    System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                    if (Delta_TS <= ClockSkew) {
                        System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);

                        String VerifyingSignature_1 = Hash(R_ID + " " + ReceivedTS);

                        if (RSA_verify(VerifyingSignature_1, stringSignature_1, publicKey_OSS_MVR)) {
                            System.out.println(TEXT_GREEN + "Signatures are Matching..............." + TEXT_RESET);
                            System.out.println(TEXT_BLUE + S_ID + " is recorded for a possible migration......." + TEXT_RESET);

                            //Nonce Verification
                            if (DecryptedPayloadArray_1[3].equals(Hash128(n_r + ReceivedTS))) {
                                System.out.println(TEXT_GREEN + "MVR Nonce is Verified ==> MVR AUTHENTICATED..............." + TEXT_RESET);

                                if (Check_ID(DecryptedPayloadArray_1[0], MVR_ID)) {
                                    System.out.println(TEXT_GREEN + "MVR_ID is matching in the Received Message..............." + TEXT_RESET);

                                    PF2 = DecryptedPayloadArray_1[1];
                                    SECRET_KEY = Create_ECDH_SecretKey(PF2,PF1,kpF);

                                    String DecryptedSecretPayload_1 = AES_Decrypt(DecryptedPayloadArray_1[2]);
                                    String[] DecryptedSecretPayloadArray_1 = DecryptedSecretPayload_1.split(" ");

                                    MES_VER = new Boolean(DecryptedSecretPayloadArray_1[0]);
                                    MES_CODE = DecryptedSecretPayloadArray_1[1];

                                    System.out.println("MES Verification [boolean] : " + MES_VER);
                                    System.out.println("MES CODE : " + MES_CODE);

                                    VerticalSpace();
                                    System.out.println("%%%%%%%%%%%%%%%%%%%%%% MESSAGE 2 COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                                    System.out.println("%%%%%%%%%%%%%%%%%%%%%% MVR COMMUNICATION COMPLETE and MES VERIFICATION DONE %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                                    PET[loop_No][6] = System.nanoTime();
                                    VerticalSpace();
                                    exit = true;
                                    ProtocolMsgCount = 2;

                                    out.println("ACK_F1");

                                } else
                                    System.out.println(TEXT_RED + "MVR_IDs Does not match..............." + TEXT_RESET);
                            } else {
                                System.out.println(TEXT_RED + "MVR Nonce is NOT Verified..............." + TEXT_RESET);
                                System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                                out.println("RETRANSMIT_F1");
                                NonceVerifierCount++;
                                if (NonceVerifierCount == 3) exit(0);
                            }
                        } else {
                            System.out.println(TEXT_RED + "Signatures Does not match..............." + TEXT_RESET);
                            System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED..............." + TEXT_RESET);

                            out.println("RETRANSMIT_F1");
                            SignatureFailCount++;
                            if (SignatureFailCount == 3) exit(0);
                        }
                    } else {

                        System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                        System.out.println(TEXT_RED + "MESSAGE DISCARDED................." + TEXT_RESET);
                        exit(0);

                    }
                } else {
                    System.out.println(TEXT_PURPLE + "MESSAGE NOT RECOGNIZED.............==> DISCARDED" + TEXT_RESET);
                    VerticalSpace();
                }
            }

            in.close();
            out.close();
            MVR_socket.close();

            T_R_F = System.nanoTime();

            System.out.println("Time taken for the conclusion of PROTOCOL SEGMENT F (T_F) [ms]: " + CheckTS(T_R_D, T_R_F));


            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  FINAL MESSAGE to gNBs PRIOR tO MIGRATION SESSION %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            //S_IP_Address = InetAddress.getLocalHost();

            Socket S1_socket = new Socket(S_IP_Address, S2_PORT);

            //BufferedReader in = new BufferedReader(new InputStreamReader(TTP_socket.getInputStream()));
            //PrintWriter out = new PrintWriter(new OutputStreamWriter(TTP_socket.getOutputStream()));

            in = new BufferedReader(new InputStreamReader(S1_socket.getInputStream()));
            out = new PrintWriter(S1_socket.getOutputStream(), true);

            SECRET_KEY = Create_ECDH_SecretKey(PE1,PF1,kpF);

            Current_time = System.nanoTime();

            //AES Payload
            String S_SecretPayload_2 = MES_RES + " " + MES_CODE;
            String S_EncryptedSecretPayload_2 = AES_Encrypt(S_SecretPayload_2);
            System.out.println("Secret Payload : "+S_EncryptedSecretPayload_2);
            System.out.println("Secret Payload Size: "+S_EncryptedSecretPayload_2.length());
            System.out.println("PF1 Size: "+PF1.length());
            System.out.println("PF2 Size: "+PF2.length());

            String S_Payload_2 = R_ID + " " + PF1 + " " + PF2 +" " + S_EncryptedSecretPayload_2 + " " + Current_time;
            System.out.println("Payload Size: "+S_Payload_2.length());

            //String S_HMAC_2 = Hash(R_ID + MES_RES + MES_CODE + Current_time);
            byte[] S_EncryptedPayloadBytes_2 = RSA_encrypt(S_Payload_2, publicKey_gNBs);
            String S_EncryptedPayload_2 = Base64.getEncoder().encodeToString(S_EncryptedPayloadBytes_2);
            System.out.println("Encrypted Payload 2 : " + S_EncryptedPayload_2);
            String S_Message_2 = "R_MES_REP" + " " + S_EncryptedPayload_2;
            PET[loop_No][7] = System.nanoTime();


            out.println(S_Message_2);
            Sending_time = System.nanoTime();
            TST[loop_No][3] = Sending_time;

            System.out.println("Message 2 : " + S_Message_2);

            //System.out.println("Hash length [bytes]: " + S_HMAC_2.getBytes().length);
            System.out.println("Payload 2 length [bytes]: " + S_Payload_2.getBytes().length);
            System.out.println("Message 2 length [bytes]: " + S_Message_2.getBytes().length);


            System.out.println("Message 2 to gNBs Sent at " + new Timestamp(System.currentTimeMillis()));

            VerticalSpace();

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   GENERATE MIGRATION MASTER SESSION KEY   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            System.out.println("n_s : " + n_s);
            System.out.println("n_r : " + n_r_key);
            System.out.println("r1 x r2 mod N : " + r1.multiply(r2).mod(N).toString());

            K_M = Hash_Key(n_s + n_r_key + (r1.multiply(r2).mod(N).toString()));

            System.out.println("Generated Migration Session Key [K_M] : " + K_M);

            SECRET_KEY = K_M;

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   MIGRATION SESSION   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


            startListening_G(S3_PORT);

            Entity_End_time = System.nanoTime();

            System.out.println("The time taken for the gNBr Operation [ms] : " + CheckTS(Entity_Start_time, Entity_End_time));

            in.close();
            out.close();
            S1_socket.close();

            VerticalSpace();
            VerticalSpace();

            System.out.println("Displaying the Timing Values................\n\n\n");

            for(int x = 0; x < loop_No; x++){
                System.out.println("TET : ");
                for(int y = 0; y < 5; y++){
                    System.out.print(", "+TET[x][y]);
                }
                System.out.println();
            }

            for(int x = 0; x < loop_No; x++){
                System.out.println("TST : ");
                for(int y = 0; y < 5; y++){
                    System.out.print(", "+TST[x][y]);
                }
                System.out.println();
            }

            for(int x = 0; x < loop_No; x++){
                System.out.println("PET : ");
                for(int y = 0; y < 9; y++){
                    System.out.print(", "+PET[x][y]);
                }
                System.out.println();
            }

            loop_No++;
        }


    }



    public static void main(String[] args) throws IOException, NoSuchAlgorithmException,InvalidKeySpecException,Exception {

        System.out.println("The MEC Roaming gNodeB Service is Running................\n\n\n");

        Roaming_gNB gNBr_server_1 = new Roaming_gNB();


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

    private void startListening_G(int port)throws IOException
    {
            listener = CreateListeningSocket(port);
            //acceptedSocket = es.submit( new ServAccept( listener ) );
        Socket serverSocket = listener.accept();

        BufferedReader in = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
        PrintWriter out = new PrintWriter(new OutputStreamWriter(serverSocket.getOutputStream()), true);

        try {

            input = in.readLine();

                Received_time = System.nanoTime();
                TET[loop_No][4] = Received_time;

                System.out.println("Message 1 from gNBs: " + input + " received at.." + new Timestamp(Received_time));
                String G_Message_1[] = input.split(" ");
                String MIH = G_Message_1[0];

                if (Check_MIH(MIH, "S_MS_INIT")) {

                    System.out.println(TEXT_GREEN+"The Received MIH matches with the Migration Session Initiation Request....."+TEXT_RESET);

                    String G_DecryptedPayload_1 = AES_Decrypt(G_Message_1[1]);
                    String G_DecryptedPayloadArray_1[] = G_DecryptedPayload_1.split("SPLIT");

                    ReceivedTS = new Long(G_DecryptedPayloadArray_1[1]);
                    Delta_TS = CheckTS(ReceivedTS, Received_time);

                    System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                    if (Delta_TS <= ClockSkew) {

                        System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);


                        String G_HMAC = Hash(G_DecryptedPayloadArray_1[0] + ReceivedTS);
                        System.out.println("Received HMAC 1: " + G_Message_1[2]);
                        System.out.println("Formed HMAC 1: " + G_HMAC);

                        if (CheckHash(G_Message_1[2], G_HMAC)) {

                            System.out.println(TEXT_GREEN + "The Hashed MACs are MATCHING ==> INTEGRITY SECURED.............." + TEXT_RESET);

                            String SecurityProfiles[] = G_DecryptedPayloadArray_1[0].split(" ");

                            for(int x=0; x < 3; x++){
                                String SecurityProfileLayers[] = SecurityProfiles[x].split("<");
                                for(int y=0; y < 5; y++){
                                    SecurityProfile[x][y] = new ArrayList<>();
                                    SecurityProfile[x][y].add(SecurityProfileLayers[y+1]);
                                }
                            }

                            VerticalSpace();
                            System.out.println("Received Security Profiles :");
                            for(int x=0; x < 3; x++){
                                for(int y=0; y < 5; y++){
                                    System.out.print(SecurityProfile[x][y].toString()+" ");
                                }
                                System.out.println();
                            }
                            PET[loop_No][8] = System.nanoTime();

                            VerticalSpace();
                        } else {
                            System.out.println(TEXT_RED + "The Hashed MACs are NOT MATCHING ==> INTEGRITY VIOLATED.............." + TEXT_RESET);
                            System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                            out.println("RETRANSMIT_C0");
                        }
                    } else {

                        System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                        System.out.println(TEXT_RED + "DISCARD MESSAGE................." + TEXT_RESET);
                    }
                } else {
                    System.out.println(TEXT_RED+"The Received MIH DOES NOT match with the Serving Migration Request of gNBs....."+TEXT_RESET);
                    System.out.println(TEXT_RED+"DISCARD MESSAGE....."+TEXT_RESET);
                }

                //%%%%%%%%%%%%%%%%%%%%%%%%%%%   REPLY MESSAGE   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            String SPI = "00002";
            Current_time = System.nanoTime();

            String G_Payload_2 = SPI+" "+Current_time;
            String G_EncryptedPayload_2 = AES_Encrypt(G_Payload_2);
            String G_Message_2 = "R_MS_REP" + " " + G_EncryptedPayload_2;
            TST[loop_No][4] = System.nanoTime();

            out.println(G_Message_2);

            System.out.println("Message : " + G_Message_2);
            System.out.println("Payload length [bytes]: " + G_Payload_2.getBytes().length);
            System.out.println("Message length [bytes]: " + G_Message_2.getBytes().length);
            System.out.println("Message Sent at " + new Timestamp(System.currentTimeMillis()));


            System.out.println(TEXT_GREEN+"SELECTED SECURITY PROFILE SUCCESSFULLY TRANSFERRED TO gNBs"+TEXT_RESET);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // Clean up
            try {
                in.close();
                out.close();
                serverSocket.close();
                listener.close();

                System.out.println("gNBs Listening Connection...Stopped");
                VerticalSpace();
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }

    }

    private void startListening(int port)throws IOException
    {
        listener = CreateListeningSocket(port);
        //acceptedSocket = es.submit( new ServAccept( listener ) );
        Socket serverSocket = listener.accept();

        BufferedReader in = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
        PrintWriter out = new PrintWriter(new OutputStreamWriter(serverSocket.getOutputStream()), true);

        ProtocolMsgCount = 0;
        try {

            exit = false;
            while(exit == false) {

                if(ProtocolMsgCount % 2 == 0) {
                    input = in.readLine();
                }

                Entity_Start_time = System.nanoTime();
                TET[loop_No][0] = Entity_Start_time;
                Received_time = System.nanoTime();

                System.out.println("Message 1 from gNBs: " + input + " received at.." + new Timestamp(Received_time));
                String Message_1[] = input.split(" ");
                String MIH = Message_1[0];

                if (Check_MIH(MIH, "S_MA_REQ")) {

                    System.out.println(TEXT_GREEN+"The Received MIH matches with the Serving Migration Request of gNBs....."+TEXT_RESET);
                    S_ID = Message_1[1];
                    publicKey_gNBs = RSA_load_public_key(Common_RSA_Certificate_Path, Entity_gNBs);

                    String EncryptedPayload_1 = Message_1[2];
                    String stringSignature_1 = Message_1[3];
                    System.out.println("Encrypted Payload : " + EncryptedPayload_1);
                    String DecryptedPayload_1 = RSA_decrypt(EncryptedPayload_1, privateKey_gNBr);
                    System.out.println("Decrypted Payload : " + DecryptedPayload_1);
                    String[] DecryptedPayloadArray_1 = DecryptedPayload_1.split(" ");

                    ReceivedTS = new Long(DecryptedPayloadArray_1[5]);
                    Delta_TS = CheckTS(ReceivedTS, Received_time);

                    System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                    if (Delta_TS <= ClockSkew) {

                        System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);
                        TTP_ID = DecryptedPayloadArray_1[0];
                        MP_ID = DecryptedPayloadArray_1[1];
                        TTP_M_PORT = new Integer(DecryptedPayloadArray_1[2]);
                        n_s = DecryptedPayloadArray_1[3];
                        PC1 = DecryptedPayloadArray_1[4];

                        String HMAC_1 = Hash(TTP_ID + MP_ID + TTP_M_PORT + n_s + PC1 + R_ID + ReceivedTS);
                        System.out.println("Received HMAC 1: " + Message_1[4]);
                        System.out.println("Formed HMAC 1: " + HMAC_1);

                        if (CheckHash(Message_1[4], HMAC_1)) {

                            System.out.println(TEXT_GREEN + "The Hashed MACs are MATCHING ==> INTEGRITY SECURED.............." + TEXT_RESET);
                            String VerifyingSignature_1 = Hash(R_ID + " " + ReceivedTS);

                            if (RSA_verify(VerifyingSignature_1, stringSignature_1, publicKey_gNBs)) {
                                System.out.println(TEXT_GREEN + "Signatures are Matching..............." + TEXT_RESET);
                                System.out.println(TEXT_BLUE + S_ID + " is recorded for a possible migration......." + TEXT_RESET);

                                System.out.println("Received TTP ID  : " + TTP_ID);
                                System.out.println("Received MP ID  : " + MP_ID);
                                System.out.println("Received TTP Port Number  : " + TTP_M_PORT);
                                System.out.println("Received PA2  : " + PC1);
                                ProtocolMsgCount = 1;
                                VerticalSpace();

                                System.out.println("%%%%%%%%%%%%%%%%%%%%%% MESSAGE 1 FROM gNBs COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                                PET[loop_No][0] = System.nanoTime();
                                VerticalSpace();
                            } else {
                                System.out.println(TEXT_RED + "Signatures Does not match..............." + TEXT_RESET);
                                System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED..............." + TEXT_RESET);

                                out.println("RETRANSMIT_C0");

                                SignatureFailCount++;
                                if (SignatureFailCount == 3) exit(0);
                            }
                        } else {
                            System.out.println(TEXT_RED + "The Hashed MACs are NOT MATCHING ==> INTEGRITY VIOLATED.............." + TEXT_RESET);
                            System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                            out.println("RETRANSMIT_C0");
                        }
                    } else {

                        System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                        System.out.println(TEXT_RED + "DISCARD MESSAGE................." + TEXT_RESET);
                    }
                } else {
                    System.out.println(TEXT_RED+"The Received MIH DOES NOT match with the Serving Migration Request of gNBs....."+TEXT_RESET);
                    System.out.println(TEXT_RED+"DISCARD MESSAGE....."+TEXT_RESET);
                }
                if(ProtocolMsgCount == 1){
                    out.println("ACK_C0");
                    System.out.println(TEXT_BLUE+"ACKNOWLEDGEMENT SENT"+TEXT_RESET);
                    exit = true;
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

                System.out.println("gNBs Listening Connection...Stopped");
                VerticalSpace();
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

        for (int x = 0; x < ID_Range; x++){

            MP_IDs[x] = RandomNonceGenerator();

        }

        String MP_ID_Array = null;

        for(int x = 0 ; x < ID_Range ; x++){

            MP_ID_Array = MP_ID_Array+"SPACE"+MP_IDs[x];
        }

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

    public static String Hash_Key (String message) throws NoSuchAlgorithmException {
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

        privateKey_gNBr = privateKey;

        String stringPublicKey = new String(Files.readAllBytes(Paths.get(Certificate_Path+"PUBLIC_KEY_"+Entity_Name+".txt")));

        System.out.println("Loaded String Public Key : "+stringPublicKey);

        byte[] decodedPublicKey = Base64.getDecoder().decode(stringPublicKey);

        KeySpec keySpecPublic = new X509EncodedKeySpec(decodedPublicKey);

        PublicKey publicKey = kf.generatePublic(keySpecPublic);

        publicKey_gNBr = publicKey;

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
        //byte[] plainTextArray = plainText.getBytes();

        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

        //Initialize Cipher for DECRYPT_MODE
        //cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        //Perform Decryption
        //return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));

        System.out.println("Private Key for Signing : "+privateKey);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(plainText.getBytes());

        byte[] signatureBytes = signature.sign();

        return Base64.getEncoder().encodeToString(signatureBytes);

        //return signatureBytes;
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
        //byte[] signatureArray = Base64.getDecoder().decode(signature);

        //Get Cipher Instance RSA With ECB Mode and OAEPWITHSHA-512ANDMGF1PADDING Padding
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-512ANDMGF1PADDING");

        //Initializing the Cipher only with the RSA without any padding or a BLock Cipher Mode
        //Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        //Initialize Cipher for DECRYPT_MODE for VERIFYING
        //cipher.init(Cipher.DECRYPT_MODE, publicKey);

        //Perform Verifying
        //return new String(cipher.doFinal(signatureArray));
        Signature signature = Signature.getInstance("SHA256withRSA");

        signature.initVerify(publicKey);
        signature.update(VerifyingSignature.getBytes());

        byte[] signatureBytes = Base64.getDecoder().decode(signatureString);

        return signature.verify(signatureBytes);

        //return new String(Base64.getDecoder().decode(signatureString));

    }

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

    public static String Generate_ECDH_SharingKey_D(int Key_Size)throws NoSuchAlgorithmException{
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(Key_Size);
        kpD = kpg.generateKeyPair();
        byte[] SharingKey = kpD.getPublic().getEncoded();

        String SK = encodeHexString(SharingKey);
        System.out.println("Sharing Key: "+SK);
        return SK;
    }

    public static String Generate_ECDH_SharingKey_C2(int Key_Size)throws NoSuchAlgorithmException{
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(Key_Size);
        kpC2 = kpg.generateKeyPair();
        byte[] SharingKey = kpC2.getPublic().getEncoded();

        String SK = encodeHexString(SharingKey);
        System.out.println("Sharing Key: "+SK);
        return SK;
    }

    public static String Generate_ECDH_SharingKey_F(int Key_Size)throws NoSuchAlgorithmException{
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(Key_Size);
        kpF = kpg.generateKeyPair();
        byte[] SharingKey = kpF.getPublic().getEncoded();

        String SK = encodeHexString(SharingKey);
        System.out.println("Sharing Key: "+SK);
        return SK;
    }

    public static String Generate_ECDH_SharingKey_E1(int Key_Size)throws NoSuchAlgorithmException{
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(Key_Size);
        kpE1 = kpg.generateKeyPair();
        byte[] SharingKey = kpE1.getPublic().getEncoded();

        String SK = encodeHexString(SharingKey);
        System.out.println("Sharing Key: "+SK);
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