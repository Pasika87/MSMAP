/**
 * Program Name : Security Protocol for MEC Service Migration - SOurce gNB
 * Version : FINAL
 * Authors : P.S.Ranaweera
 *
 * Language : Java
 * Date : 06/06/2022
 * */


package StandardProtocol;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.sql.Timestamp;

import static java.lang.System.exit;

public class Source_gNB {

    /**
     * Variable Definitions
     */
    public static int OSS_CA_PORT = 999;
    public static int TTP_PORT;
    public static int R_PORT = 2000;
    public static int S_PORT = 900;
    public static int R1_PORT = 9000;
    public static int R2_PORT = 9500;
    public static int R3_PORT = 9700;
    public static int MVR_PORT = 10000;
    public static int MVR_PORT1 = 10100;
    public static int K_DOS = 4; //The Complexity value of the DoS Puzzle

    public static int RSA_Key_length = 4096; //bits
    public static int AES_Key_Length = 256; //bits
    public static int ECDH_Key_Length_1 = 256; //bits
    public static int ECDH_Key_Length_2 = 128; //bits
    public static int ECDH_Key_Length_3 = 112; //bits

    String S_ID = "10.0.0.1";
    String OSS_ID = "10.0.0.2";
    String R_ID = "10.0.0.3";
    String TTP_ID;
    String MVR_ID = "10.0.0.4";

    public static long Entity_Start_time;
    public static long Entity_End_time;
    public static long Process_time;
    public static long Received_time;
    public static long Sending_time;
    public static long Current_time;
    public static long ClockSkew = 5000;    //Defined Clock Skew : 5 seconds
    public static long Delta_TS;
    public static long ReceivedTS;
    public long T_S_A, T_S_B;

    public static String Plaintext;

    public static String encryptedString;

    public String K_dos_OSS, n_oss, K_dos_TTP, n_ttp;

    public PublicKey publicKey_OSS_CA, publicKey_gNBs, publicKey_gNBr, publicKey_OSS_MVR, publicKey_TTP;

    public PrivateKey privateKey_gNBs;

    public PublicKey signingKey_gNBs;

    public static String Common_RSA_Certificate_Path = "E:/OneDrive/PhD Ireland/PhD Work/MEC/Research Directions/Service Migration Prediction/Implementation/MECMigrationProtocol/out/production/MECMigrationProtocol/";

    public static String Entity_gNBs = "gNBs", Entity_gNBr = "gNBr", Entity_OSS_CA = "OSS_CA", Entity_OSS_MVR = "OSS_MVR", Entity_TTP = "TTP";

//Defining Prime value size for the RSA Encryption Scheme
    //static final int RSA_bit_length = 1028;

    //Defining RSA public parameters for the StandardProtocol.OSS_CA
    static BigInteger e_oss, N_oss, d_oss;
    //Defining RSA public and private parameters for the StandardProtocol.Source_gNB
    static BigInteger e_s, N_s, d_s;
    //Defining RSA public parameters for the Roaming gNB
    static BigInteger e_r, N_r;
    //Defining RSA public parameters for the TTP
    static BigInteger e_ttp, N_ttp;
    //Defining RSA public parameters for the StandardProtocol.OSS_MVR
    static BigInteger e_mvr, N_mvr;

    //AES Variables
    public static SecretKeySpec AES_secretKey;
    public static byte[] AES_key;
    public static byte[] iv;

    //ECDH VAriables

    public static KeyPair kpA, kpB, kpC1, kpC2, kpE1, kpE2;
    public static String PA1, PA2, PB1, PB2, PC1, PC2, PC3, PE1, PF1, PF2;

    //Secret Key and Salt for the AESEncrypt() and AESDecrypt() Functions
    public static String SECRET_KEY;
    public static final String SALT = "ssshhhhhhhhhhh!!!!";

    public ServerSocket listener;

    public int TTP_M_PORT;
    public String X;
    public String n_s, n_r, M_CODE;
    public String[] MP_IDs;
    public String MES_ID;
    public static boolean MES_VER = true;
    public static String MES_CODE;
    public static boolean MES_RES;
    public static String K_M;

    public InetAddress OSS_IP_Address = InetAddress.getByAddress(new byte[]{(byte)193, (byte)1, (byte)132, (byte)81});

    public InetAddress TTP_IP_Address;

    public InetAddress R_IP_Address;

    public InetAddress MVR_IP_Address;

    public BigInteger r1_dash, r2_dash;

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

    public boolean exit = false;

    public int SignatureFailCount;
    public int NonceVerifierCount;
    public int ProtocolMsgCount;

    public ArrayList<String>[][] SecurityProfile;

    public static int N_Messages = 16;
    public static int N_Trials = 22;

    public static Long[] EST; //Entity Start Time
    public static Long[][] PET; //Process End Time ==> Indicating the end time of each processed message prior to transmission
    public static Long[][] TST; //Transmission Start Time ==> Indicating the starting time at the sender end
    public static Long[][] TET; //Transmission End Time ==> Indicating the received time time at the receiver end
    public static Long[] EET; //Entity End Time
    public int loop_No = 0;

    //Definition of Input Buffered Reader and Output Print writer for sending and Receiving messages through the socket
    //BufferedReader in;
    //PrintWriter out;

    public Source_gNB() throws IOException,NoSuchAlgorithmException,NullPointerException, InvalidKeySpecException, Exception {

        RSA_load_own_keys(Common_RSA_Certificate_Path,Entity_gNBs);

        publicKey_OSS_CA = RSA_load_public_key(Common_RSA_Certificate_Path,Entity_OSS_CA);

        System.out.println("PRIVATE KEY of gNBs : "+privateKey_gNBs);

        //signingKey_gNBs = RSA_load_Signing_key(Common_RSA_Certificate_Path,Entity_gNBs);

        OSS_IP_Address = InetAddress.getLocalHost();
        //Socket Connection Establishment
        System.out.println("IP : "+OSS_IP_Address);

        Scanner Sc = new Scanner(System.in);


        EST = new Long[N_Trials];
        PET = new Long[N_Trials][N_Messages];
        TST = new Long[N_Trials][N_Messages];
        TET = new Long[N_Trials][N_Messages];
        EET = new Long[N_Trials];


        boolean loop = true;
        boolean FirstTime = true;

        while (loop == true) {

            SecurityProfile = new ArrayList[3][5];

            Socket OSS_CA_socket = new Socket(OSS_IP_Address,OSS_CA_PORT);
            BufferedReader in = new BufferedReader(new InputStreamReader(OSS_CA_socket.getInputStream()));
            PrintWriter out = new PrintWriter(OSS_CA_socket.getOutputStream(), true);

            if(FirstTime == true){
                //TEST MESSAGE FORMATION TO FINE TUNE THE SYSTEM FOR CRYPTO OPERATIONS
                String Pre_Signature = Hash(OSS_ID + " " + Current_time);
                String Signature = RSA_sign(Pre_Signature, privateKey_gNBs);
                String Payload = S_ID + " " + Current_time;
                //System.out.println("Signature : " + Signature);
                //System.out.println("Size of the Signature : " + Signature.length());
                String HMAC = Hash(OSS_ID + S_ID + Current_time);
                byte[] EncryptedPayloadBytes = RSA_encrypt(Payload, publicKey_OSS_CA);
                String EncryptedPayload = Base64.getEncoder().encodeToString(EncryptedPayloadBytes);
                //System.out.println("Encrypted Payload 1 : " + EncryptedPayload);
                String Message = "Hello" + " " + EncryptedPayload + " " + Signature + " " + HMAC;

            }


            FirstTime = false;
            SignatureFailCount = 0;
            NonceVerifierCount = 0;
            ProtocolMsgCount = 0;
            exit = false;

            VerticalSpace();
            System.out.println(TEXT_BLUE+"%%%%%%%%%%%%%%%%%         The Source gNB is OPERATING      %%%%%%%%%%%%%%%%%%%%");
            System.out.println("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"+TEXT_RESET);
            VerticalSpace();

            //%%%%%%%%%%%%%%%%%%%%%%%%%%    Communication with the OSS CA FUNCTION  %%%%%%%%%%%%%%%%%%%%%%%%%%%%


            while (exit == false) {



                if (ProtocolMsgCount % 2 != 0) {

                    input = in.readLine();
                }

                if ((ProtocolMsgCount == 0) || (input.startsWith("RETRANSMIT_A0"))) {

                    Entity_Start_time = System.nanoTime();
                    System.out.println("Entity Start Time [ms]: "+Entity_Start_time);
                    EST[loop_No] = Entity_Start_time;


                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 1  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    PA1 = Generate_ECDH_SharingKey_A(ECDH_Key_Length_1);

                    Current_time = System.nanoTime();
                    String Pre_Signature_1 = Hash(OSS_ID + " " + Current_time);
                    String Signature_1 = RSA_sign(Pre_Signature_1, privateKey_gNBs);

                    String Payload_1 = S_ID + " " +PA1+ " " + Current_time;
                    System.out.println("Signature : " + Signature_1);
                    System.out.println("Size of the Signature : " + Signature_1.length());

                    String HMAC_1 = Hash(S_ID + PA1 + OSS_ID + Current_time);
                    byte[] EncryptedPayloadBytes_1 = RSA_encrypt(Payload_1, publicKey_OSS_CA);
                    String EncryptedPayload_1 = Base64.getEncoder().encodeToString(EncryptedPayloadBytes_1);
                    System.out.println("Encrypted Payload 1 : " + EncryptedPayload_1);
                    String Message_1 = "Hello" + " " + EncryptedPayload_1 + " " + Signature_1 + " " + HMAC_1;

                    PET[(loop_No)][0] = System.nanoTime();

                    out.println(Message_1);

                    Sending_time = System.nanoTime();
                    System.out.println("Message 1 Sending Time [ms]: " + Sending_time);
                    TST[(loop_No)][0] = System.nanoTime();

                    System.out.println("Message 1 : " + Message_1);
                    System.out.println("Message Process Time [ms]:" + CheckTS(Current_time, Sending_time));
                    System.out.println("Hash length [bytes]: " + HMAC_1.getBytes().length);
                    System.out.println("Payload 1 length [bytes]: " + Payload_1.getBytes().length);
                    System.out.println("Message 1 length [bytes]: " + Message_1.getBytes().length);

                    System.out.println("Message 1 Sent at " + new Timestamp(Sending_time));

                    ProtocolMsgCount = 1;
                    VerticalSpace();

                } else if (ProtocolMsgCount == 1) {

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 2  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    Received_time = System.nanoTime();
                    TET[loop_No][0] = Received_time;
                    System.out.println("Message 2 from StandardProtocol.OSS_CA: " + input + " received at.." + new Timestamp(Received_time));
                    String Message_2[] = input.split(" ");
                    String EncryptedPayload_2 = Message_2[0];
                    String stringSignature_2 = Message_2[1];
                    System.out.println("Encrypted Payload : " + EncryptedPayload_2);
                    String DecryptedPayload_2 = RSA_decrypt(EncryptedPayload_2, privateKey_gNBs);
                    System.out.println("Decrypted Payload : " + DecryptedPayload_2);
                    String[] DecryptedPayloadArray_2 = DecryptedPayload_2.split(" ");

                    ReceivedTS = new Long(DecryptedPayloadArray_2[4]);
                    Delta_TS = CheckTS(ReceivedTS, Received_time);
                    System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                    if (Delta_TS <= ClockSkew) {

                        System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);
                        String HMAC_2 = Hash(DecryptedPayloadArray_2[1] + DecryptedPayloadArray_2[2] + DecryptedPayloadArray_2[3] + S_ID + ReceivedTS);
                        System.out.println("Received HMAC 2: " + Message_2[2]);
                        System.out.println("Formed HMAC 2: " + HMAC_2);

                        if (CheckHash(Message_2[2], HMAC_2)) {
                            System.out.println(TEXT_GREEN + "The Hashed MACs are MATCHING ==> INTEGRITY SECURED.............." + TEXT_RESET);

                            if (Check_MIH(DecryptedPayloadArray_2[0], "OSS_TD_REP")) {
                                System.out.println(TEXT_GREEN + "MIHs are matching in the Received Message..............." + TEXT_RESET);
                                String VerifyingSignature_2 = Hash(S_ID + " " + ReceivedTS);

                                if (RSA_verify(VerifyingSignature_2, stringSignature_2, publicKey_OSS_CA)) {
                                    System.out.println(TEXT_GREEN + "Signatures are Matching..............." + TEXT_RESET);

                                    K_DOS = new Integer(DecryptedPayloadArray_2[1]);
                                    n_oss = DecryptedPayloadArray_2[2];
                                    PA2 = DecryptedPayloadArray_2[3];
                                    System.out.println("Received K-DOS Value : " + K_DOS);
                                    System.out.println("Received OSS Nonce : " + n_oss);
                                    System.out.println("Received ECC Shared Key PA2 : " + PA2);

                                    ProtocolMsgCount = 2;
                                    VerticalSpace();
                                    System.out.println("%%%%%%%%%%%%%%%%%%%%%% MESSAGE 2 COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");

                                    System.out.println("Message Completion Time [ms]:" + CheckTS(Received_time, System.nanoTime()));
                                    PET[loop_No][1] = System.nanoTime();

                                } else {
                                    System.out.println(TEXT_RED + "Signatures Does not match..............." + TEXT_RESET);
                                    System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED..............." + TEXT_RESET);
                                    out.println("RETRANSMIT_A1");
                                }

                            } else System.out.println("MIHs Does not match...............");
                        } else {
                            System.out.println(TEXT_RED + "The Hashed MACs are NOT MATCHING ==> INTEGRITY VIOLATED.............." + TEXT_RESET);
                            System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);
                            out.println("RETRANSMIT_A1");
                        }
                    } else {
                        System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                        System.out.println(TEXT_RED + "MESSAGE DISCARDED................." + TEXT_RESET);
                        exit(0);
                    }
                } else if ((ProtocolMsgCount == 2) || (input.startsWith("RETRANSMIT_A2"))) {

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 3  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    n_s = RandomNonceGenerator();
                    System.out.println("Generated S Nonce for OSS [Ns] : " + n_s);
                    X = DoS_Puzzle(K_DOS, publicKey_gNBs.toString(), S_ID, OSS_ID, n_s, n_oss);
                    System.out.println("X : " + X);
                    Current_time = System.nanoTime();

                    String Payload_3 = "S_TD_REP" + " " + n_s + " " + X + " " + Hash(n_oss + Current_time) + " " + Current_time;
                    String HMAC_3 = Hash(n_s + X + Hash(n_oss + Current_time) + Current_time);
                    byte[] EncryptedPayloadBytes_3 = RSA_encrypt(Payload_3, publicKey_OSS_CA);
                    String EncryptedPayload_3 = Base64.getEncoder().encodeToString(EncryptedPayloadBytes_3);
                    System.out.println("Encrypted Payload 3 : " + EncryptedPayload_3);
                    String Message_3 = EncryptedPayload_3 + " " + HMAC_3;
                    PET[loop_No][2] = System.nanoTime();

                    out.println(Message_3);

                    Sending_time = System.nanoTime();
                    TST[loop_No][1] = Sending_time;
                    System.out.println("Message 3 : " + Message_3);
                    System.out.println("Message Process Time [ms]:" + CheckTS(Current_time, Sending_time));
                    System.out.println("Hash length [bytes]: " + HMAC_3.getBytes().length);
                    System.out.println("Payload 3 length [bytes]: " + Payload_3.getBytes().length);
                    System.out.println("Message 3 length [bytes]: " + Message_3.getBytes().length);
                    System.out.println("Message 3 Sent at " + new Timestamp(Sending_time));

                    ProtocolMsgCount = 3;
                    VerticalSpace();

                } else if (ProtocolMsgCount == 3) {

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 4  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                    Received_time = System.nanoTime();
                    TET[loop_No][1] = Received_time;
                    SECRET_KEY = Create_ECDH_SecretKey(PA2,PA1,kpA);

                    System.out.println("Message 4 from StandardProtocol.OSS_CA: " + input + " received at.." + new Timestamp(Received_time));
                    String Message_4[] = input.split(" ");
                    String EncryptedPayload_4 = Message_4[0];
                    System.out.println("Encrypted Payload : " + EncryptedPayload_4);
                    String DecryptedPayload_4 = RSA_decrypt(EncryptedPayload_4, privateKey_gNBs);
                    System.out.println("Decrypted Payload : " + DecryptedPayload_4);
                    String[] DecryptedPayloadArray_4 = DecryptedPayload_4.split("SPLIT");

                    ReceivedTS = new Long(DecryptedPayloadArray_4[4]);
                    Delta_TS = CheckTS(ReceivedTS, Received_time);
                    System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                    if (Delta_TS <= ClockSkew) {

                        System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);
                        TTP_ID = DecryptedPayloadArray_4[1];

                        String DecryptedSecretPayload_4 = AES_Decrypt(DecryptedPayloadArray_4[2]);
                        String[] DecryptedSecretPayloadArray_4 = DecryptedSecretPayload_4.split("SPLIT");
                        TTP_PORT = new Integer(DecryptedSecretPayloadArray_4[0]);
                        String TTP_Certificate_Path = DecryptedSecretPayloadArray_4[1];
                        String HMAC_4 = Hash(TTP_ID + TTP_PORT + TTP_Certificate_Path + n_s + ReceivedTS);
                        System.out.println("Received HMAC 4: " + Message_4[1]);
                        System.out.println("Formed HMAC 4: " + HMAC_4);

                        if (CheckHash(Message_4[1], HMAC_4)) {
                            System.out.println(TEXT_GREEN + "The Hashed MACs are MATCHING ==> INTEGRITY SECURED.............." + TEXT_RESET);

                            //S Nonce Verifier
                            if (CheckHash(DecryptedPayloadArray_4[3], Hash256(n_s + ReceivedTS))) {
                                System.out.println(TEXT_GREEN + "The gNBs Nonce is Verified.............." + TEXT_RESET);
                                publicKey_TTP = RSA_load_public_key(TTP_Certificate_Path, Entity_TTP);
                                System.out.println("TTP IP Address : " + TTP_ID);
                                System.out.println("TTP PORT NO : " + TTP_PORT);
                                System.out.println("Loaded TTP Public Key : " + publicKey_TTP);

                                VerticalSpace();
                                System.out.println("%%%%%%%%%%%%%%%%%%%%%% MESSAGE 4 COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                                System.out.println("Message Completion Time [ms]:" + CheckTS(Received_time, System.nanoTime()));

                                out.println("COMPLETE_A");
                                System.out.println(TEXT_BLUE + "%%%%%%%%%%%%%%%%%%%%%% PROTOCOL SEGMENT A COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n" + TEXT_RESET);
                                PET[loop_No][3] = System.nanoTime();
                                ProtocolMsgCount = 4;

                                VerticalSpace();

                            } else {
                                System.out.println(TEXT_RED + "The gNBs Nonce is Verified.............." + TEXT_RESET);
                                System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);
                                out.println("RETRANSMIT_A3");

                                NonceVerifierCount++;
                                if (NonceVerifierCount == 3) exit(0);
                            }


                        } else {
                            System.out.println(TEXT_RED + "The Hashed MACs are NOT MATCHING ==> INTEGRITY VIOLATED.............." + TEXT_RESET);
                            System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);
                            out.println("RETRANSMIT_A3");
                        }
                    } else {
                        System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                        System.out.println(TEXT_RED + "MESSAGE DISCARDED................." + TEXT_RESET);
                        exit(0);

                    }

                } else if (ProtocolMsgCount == 4) {
                    T_S_A = System.nanoTime();
                    System.out.println("Time taken for the conclusion of PROTOCOL SEGMENT A (T_A) [ms]: " + CheckTS(Entity_Start_time, T_S_A));
                    VerticalSpace();

                    exit = true;
                } else {
                    System.out.println(TEXT_PURPLE + "MESSAGE NOT RECOGNIZED.............==> DISCARDED" + TEXT_RESET);
                    VerticalSpace();
                }
            }

            in.close();
            out.close();
            OSS_CA_socket.close();


            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% TTP SERVER CONNECTION  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            TTP_IP_Address = InetAddress.getLocalHost();
        /*
        TTP_IP_Address = InetAddress.getByAddress(new byte[] {
                (byte)193, (byte)1, (byte)132, (byte)81}
        );*/
            //Socket Connection Establishment
            Socket TTP_socket = new Socket(TTP_IP_Address, TTP_PORT);

            in = new BufferedReader(new InputStreamReader(TTP_socket.getInputStream()));
            out = new PrintWriter(TTP_socket.getOutputStream(), true);

            System.out.println(TEXT_BLUE + "gNBs is Connected to the TTP SERVER................" + TEXT_RESET);

            SignatureFailCount = 0;
            NonceVerifierCount = 0;
            ProtocolMsgCount = 0;
            exit = false;
            VerticalSpace();

            while (exit == false) {

                if (ProtocolMsgCount % 2 != 0) {

                    input = in.readLine();
                }

                //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 1  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                if ((ProtocolMsgCount == 0) || (input.startsWith("RETRANSMIT_B0"))) {

                    PB1 = Generate_ECDH_SharingKey_B(ECDH_Key_Length_1);

                    Current_time = System.nanoTime();
                    String TTP_Pre_Signature_1 = Hash(TTP_ID + " " + Current_time);
                    String TTP_Signature_1 = RSA_sign(TTP_Pre_Signature_1, privateKey_gNBs);

                    String TTP_Payload_1 = S_ID + " " + PB1 + " " + Current_time;
                    System.out.println("Signature : " + TTP_Signature_1);
                    System.out.println("Size of the Signature : " + TTP_Signature_1.length());

                    String TTP_HMAC_1 = Hash(S_ID + PB1 + TTP_ID + Current_time);
                    byte[] TTP_EncryptedPayloadBytes_1 = RSA_encrypt(TTP_Payload_1, publicKey_TTP);
                    String TTP_EncryptedPayload_1 = Base64.getEncoder().encodeToString(TTP_EncryptedPayloadBytes_1);
                    System.out.println("Encrypted Payload 1 : " + TTP_EncryptedPayload_1);
                    String TTP_Message_1 = "Hello" + " " + TTP_EncryptedPayload_1 + " " + TTP_Signature_1 + " " + TTP_HMAC_1;
                    PET[loop_No][4] = System.nanoTime();

                    out.println(TTP_Message_1);

                    Sending_time = System.nanoTime();
                    TST[loop_No][2] = Sending_time;
                    System.out.println("Message 1 : " + TTP_Message_1);
                    System.out.println("Hash length [bytes]: " + TTP_HMAC_1.getBytes().length);
                    System.out.println("Payload 1 length [bytes]: " + TTP_Payload_1.getBytes().length);
                    System.out.println("Message 1 length [bytes]: " + TTP_Message_1.getBytes().length);
                    System.out.println("Message 1 Sent at " + new Timestamp(Sending_time));

                    ProtocolMsgCount = 1;
                    VerticalSpace();

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 2  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                } else if (ProtocolMsgCount == 1) {
                    Received_time = System.nanoTime();
                    TET[loop_No][2] = Received_time;
                    System.out.println("Message 2 from TTP: " + input + " received at.." + new Timestamp(Received_time));
                    String TTP_Message_2[] = input.split(" ");
                    String TTP_EncryptedPayload_2 = TTP_Message_2[0];
                    String TTP_stringSignature_2 = TTP_Message_2[1];
                    System.out.println("Encrypted Payload : " + TTP_EncryptedPayload_2);
                    String TTP_DecryptedPayload_2 = RSA_decrypt(TTP_EncryptedPayload_2, privateKey_gNBs);
                    System.out.println("Decrypted Payload : " + TTP_DecryptedPayload_2);
                    String[] TTP_DecryptedPayloadArray_2 = TTP_DecryptedPayload_2.split(" ");

                    ReceivedTS = new Long(TTP_DecryptedPayloadArray_2[4]);
                    Delta_TS = CheckTS(ReceivedTS, Received_time);
                    System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                    if (Delta_TS <= ClockSkew) {

                        System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);

                        K_DOS = new Integer(TTP_DecryptedPayloadArray_2[1]);
                        n_ttp = TTP_DecryptedPayloadArray_2[2];
                        String TTP_HMAC_2 = Hash(K_DOS + n_ttp + TTP_DecryptedPayloadArray_2[3] + S_ID + ReceivedTS);
                        System.out.println("Received HMAC 2: " + TTP_Message_2[2]);
                        System.out.println("Formed HMAC 2: " + TTP_HMAC_2);

                        if (CheckHash(TTP_Message_2[2], TTP_HMAC_2)) {
                            String TTP_VerifyingSignature_2 = Hash(S_ID + " " + ReceivedTS);

                            if (RSA_verify(TTP_VerifyingSignature_2, TTP_stringSignature_2, publicKey_TTP)) {
                                System.out.println(TEXT_GREEN + "Signatures are Matching..............." + TEXT_RESET);

                                if (Check_MIH(TTP_DecryptedPayloadArray_2[0], "TTP_MR_REP")) {
                                    System.out.println(TEXT_GREEN + "MIHs are matching in the Received Message..............." + TEXT_RESET);

                                    System.out.println("Received K-DOS Value : " + K_DOS);
                                    System.out.println("Received TTP Nonce : " + n_ttp);
                                    PB2 = TTP_DecryptedPayloadArray_2[3];
                                    System.out.println("PB2 : " + PB2);
                                    VerticalSpace();

                                    System.out.println("%%%%%%%%%%%%%%%%%%%%%% MESSAGE 2 COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                                    PET[loop_No][5] = System.nanoTime();
                                    ProtocolMsgCount = 2;

                                } else System.out.println(TEXT_RED + "MIHs Does not match..............." + TEXT_RESET);
                            } else {
                                System.out.println(TEXT_RED + "Signatures Does not match..............." + TEXT_RESET);
                                System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED..............." + TEXT_RESET);

                                out.println("RETRANSMIT_B1");

                                SignatureFailCount++;
                                if (SignatureFailCount == 3) exit(0);
                            }

                        } else {
                            System.out.println(TEXT_RED + "The Hashed MACs are NOT MATCHING ==> INTEGRITY VIOLATED.............." + TEXT_RESET);
                            System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                            out.println("RETRANSMIT_B1");
                        }
                    } else {

                        System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                        System.out.println(TEXT_RED + "DISCARD MESSAGE................." + TEXT_RESET);
                    }

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 3  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                } else if ((ProtocolMsgCount == 2) || (input.startsWith("RETRANSMIT_B2"))) {

                    n_s = RandomNonceGenerator();
                    System.out.println("Generated S Nonce for TTP [Ns] : " + n_s);

                    String Q = n_s + n_ttp + X + S_ID + publicKey_gNBs.toString();
                    X = DoS_Puzzle(K_DOS, publicKey_gNBs.toString(), S_ID, TTP_ID, n_s, n_ttp);

                    System.out.println("X : " + X);

                    Current_time = System.nanoTime();
                    String Hashed_Nonce_ttp = Hash(n_ttp + Current_time);

                    String TTP_Payload_3 = "S_MR_REQ" + " " + n_s + " " + X + " " + Hashed_Nonce_ttp + " " + Current_time;

                    String TTP_HMAC_3 = Hash(n_s + X + Hashed_Nonce_ttp + Current_time);
                    byte[] TTP_EncryptedPayloadBytes_3 = RSA_encrypt(TTP_Payload_3, publicKey_TTP);
                    String TTP_EncryptedPayload_3 = Base64.getEncoder().encodeToString(TTP_EncryptedPayloadBytes_3);
                    System.out.println("Encrypted Payload 3 : " + TTP_EncryptedPayload_3);
                    String TTP_Message_3 = TTP_EncryptedPayload_3 + " " + TTP_HMAC_3;
                    PET[loop_No][6] = System.nanoTime();

                    out.println(TTP_Message_3);

                    Sending_time = System.nanoTime();
                    TST[loop_No][3] = Sending_time;
                    System.out.println("Message 3 : " + TTP_Message_3);
                    System.out.println("Hash length [bytes]: " + TTP_HMAC_3.getBytes().length);
                    System.out.println("Payload 3 length [bytes]: " + TTP_Payload_3.getBytes().length);
                    System.out.println("Message 3 length [bytes]: " + TTP_Message_3.getBytes().length);
                    System.out.println("Message 3 Sent at " + new Timestamp(Sending_time));

                    VerticalSpace();

                    ProtocolMsgCount = 3;

                    //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 4  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                } else if (ProtocolMsgCount == 3) {

                    Received_time = System.nanoTime();
                    TET[loop_No][3] = Received_time;

                    SECRET_KEY = Create_ECDH_SecretKey(PB2,PB1,kpB);

                    System.out.println("Message 4 from TTP: " + input + " received at.." + new Timestamp(Received_time));
                    String TTP_Message_4[] = input.split(" ");
                    String TTP_EncryptedPayload_4 = TTP_Message_4[0];
                    System.out.println("Encrypted Payload : " + TTP_EncryptedPayload_4);
                    String TTP_DecryptedPayload_4 = RSA_decrypt(TTP_EncryptedPayload_4, privateKey_gNBs);
                    System.out.println("Decrypted Payload : " + TTP_DecryptedPayload_4);
                    String[] TTP_DecryptedPayloadArray_4 = TTP_DecryptedPayload_4.split("SPLIT");

                    ReceivedTS = new Long(TTP_DecryptedPayloadArray_4[3]);
                    Delta_TS = CheckTS(ReceivedTS, Received_time);
                    System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                    if (Delta_TS <= ClockSkew) {

                        System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);

                        String TTP_DecryptedSecretPayload_4 = AES_Decrypt(TTP_DecryptedPayloadArray_4[1]);
                        String[] TTP_DecryptedSecretPayloadArray_4 = TTP_DecryptedSecretPayload_4.split("SPLIT");

                        TTP_M_PORT = new Integer(TTP_DecryptedSecretPayloadArray_4[0]);
                        String MP_ID_Array = TTP_DecryptedSecretPayloadArray_4[1];
                        MP_IDs = MP_ID_Array.split("SPACE");
                        r1_dash = new BigInteger(TTP_DecryptedSecretPayloadArray_4[2]);

                        String TTP_HMAC_4 = Hash(TTP_M_PORT + MP_ID_Array + r1_dash + n_s + ReceivedTS);
                        System.out.println("Received HMAC 4: " + TTP_Message_4[1]);
                        System.out.println("Formed HMAC 4: " + TTP_HMAC_4);

                        if (CheckHash(TTP_Message_4[1], TTP_HMAC_4)) {
                            //Nonce Verifier
                            if (CheckHash(TTP_DecryptedPayloadArray_4[2], Hash256(n_s + ReceivedTS))) {

                                System.out.println(TEXT_GREEN + "TTP Nonce is Verified..............." + TEXT_RESET);

                                System.out.println("TTP Migration Port : " + TTP_M_PORT);
                                System.out.println("Received MP_IDs : ");

                                for (int x = 0; x < MP_IDs.length; x++) {
                                    System.out.println(MP_IDs[x]);
                                }
                                System.out.println("%%%%%%%%%%%%%%%%%%%%%% MESSAGE 4 COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                                PET[loop_No][7] = System.nanoTime();
                                ProtocolMsgCount = 4;

                            } else {
                                System.out.println(TEXT_RED + "TTP Nonce is NOT Verified..............." + TEXT_RESET);
                                System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                                out.println("RETRANSMIT_B3");
                                NonceVerifierCount++;
                                if (NonceVerifierCount == 3) exit(0);
                            }
                        } else {
                            System.out.println(TEXT_RED + "The Hashed MACs are NOT MATCHING ==> INTEGRITY VIOLATED.............." + TEXT_RESET);
                            System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                            out.println("RETRANSMIT_B3");
                        }
                    } else {

                        System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                        System.out.println(TEXT_RED + "MESSAGE DISCARDED................." + TEXT_RESET);
                        exit(0);
                    }
                } else if (ProtocolMsgCount == 4) {

                    out.println("COMPLETE_B");
                    System.out.println(TEXT_BLUE + "%%%%%%%%%%%%%%%%%%%%%% PROTOCOL SEGMENT B COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n" + TEXT_RESET);
                    VerticalSpace();
                    T_S_B = System.nanoTime();
                    System.out.println("Time taken for the conclusion of PROTOCOL SEGMENT B (T_B) [ms]: " + CheckTS(T_S_A, T_S_B));
                    exit = true;
                } else {
                    System.out.println(TEXT_PURPLE + "MESSAGE NOT RECOGNIZED.............==> DISCARDED" + TEXT_RESET);
                    VerticalSpace();
                }
                VerticalSpace();
            }

            in.close();
            out.close();
            TTP_socket.close();


            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  gNodeB ROAMING CONNECTION  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            R_IP_Address = InetAddress.getLocalHost();

            //Socket Connection Establishment
            Socket R_socket = new Socket(R_IP_Address, R_PORT);

            in = new BufferedReader(new InputStreamReader(R_socket.getInputStream()));
            out = new PrintWriter(R_socket.getOutputStream(), true);

            System.out.println("gNBs is Connected to the gNBr................");
            exit = false;

            VerticalSpace();

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  Message 1  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            while (exit == false) {

                n_s = RandomNonceGenerator();
                System.out.println("Generated S Nonce for gNBr [Ns] : " + n_s);
                publicKey_gNBr = RSA_load_public_key(Common_RSA_Certificate_Path, Entity_gNBr);

                PC1 = Generate_ECDH_SharingKey_C1(ECDH_Key_Length_3);

                Current_time = System.nanoTime();
                String R_Pre_Signature_1 = Hash(R_ID + " " + Current_time);
                String R_Signature_1 = RSA_sign(R_Pre_Signature_1, privateKey_gNBs);
                String R_Payload_1 = TTP_ID + " " + MP_IDs[0] + " " + TTP_M_PORT + " " + n_s + " " + PC1 + " " + Current_time;
                System.out.println("Signature : " + R_Signature_1);
                System.out.println("Size of the Signature : " + R_Signature_1.length());

                String R_HMAC_1 = Hash(TTP_ID + MP_IDs[0] + TTP_M_PORT + n_s + PC1 + R_ID + Current_time);
                byte[] R_EncryptedPayloadBytes_1 = RSA_encrypt(R_Payload_1, publicKey_gNBr);
                String R_EncryptedPayload_1 = Base64.getEncoder().encodeToString(R_EncryptedPayloadBytes_1);
                System.out.println("Encrypted Payload 1 : " + R_EncryptedPayload_1);
                String R_Message_1 = "S_MA_REQ" + " " + S_ID + " " + R_EncryptedPayload_1 + " " + R_Signature_1 + " " + R_HMAC_1;
                PET[loop_No][8] = System.nanoTime();

                out.println(R_Message_1);

                Sending_time = System.nanoTime();
                TST[loop_No][4] = Sending_time;
                System.out.println("Message 1 : " + R_Message_1);
                System.out.println("Hash length [bytes]: " + R_HMAC_1.getBytes().length);
                System.out.println("Payload 1 length [bytes]: " + R_Payload_1.getBytes().length);
                System.out.println("Message 1 length [bytes]: " + R_Message_1.getBytes().length);
                System.out.println("Message 1 Sent at " + new Timestamp(Sending_time));

                input = in.readLine();

                System.out.println("Input : " + input);

                if (input.equals("ACK_C0")) {
                    exit = true;
                }

            }
            VerticalSpace();
            in.close();
            out.close();
            R_socket.close();

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% TTP SERVER FINAL CONNECTION  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            startListening_TTP_R(S_PORT);

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% gNodeB ROAMING RE CONNECTION  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            System.out.println("gNB ROAMING RE CONNECTION INITIATION........");

            startListening_R(R1_PORT);

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% gNodeB ROAMING RE CONNECTION  2   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            System.out.println("gNB ROAMING RE CONNECTION TO MES VERIFICATION INITIATION........");

            startListening_R1(R2_PORT);

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   MESSAGE TO MVR  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


            MVR_IP_Address = InetAddress.getLocalHost();

            publicKey_OSS_MVR = RSA_load_public_key(Common_RSA_Certificate_Path, Entity_OSS_MVR);

            //Socket Connection Establishment
            Socket MVR_socket = new Socket(MVR_IP_Address, MVR_PORT1);

            in = new BufferedReader(new InputStreamReader(MVR_socket.getInputStream()));
            out = new PrintWriter(MVR_socket.getOutputStream(), true);

            System.out.println("gNBs is Connected to the MVR................");

            VerticalSpace();

            exit = false;

            while (exit == false) {

                SECRET_KEY = Create_ECDH_SecretKey(PF2,PE1,kpE1);

                String MVR_SecretPayload = MES_CODE;
                String MVR_EncryptedSecretPayload = AES_Encrypt(MVR_SecretPayload);
                System.out.println("Secret Payload : "+MVR_EncryptedSecretPayload);
                System.out.println("Secret Payload Size: "+MVR_EncryptedSecretPayload.length());

                Current_time = System.nanoTime();
                String MVR_Payload = S_ID + " " + MES_ID + " " + MVR_EncryptedSecretPayload + " " + Current_time;
                byte[] MVR_EncryptedPayloadBytes = RSA_encrypt(MVR_Payload, publicKey_OSS_MVR);
                String MVR_EncryptedPayload = Base64.getEncoder().encodeToString(MVR_EncryptedPayloadBytes);
                System.out.println("Encrypted Payload : " + MVR_EncryptedPayload);
                String MVR_Message = "S_MES_VER" + " " + MVR_EncryptedPayload;
                PET[loop_No][13] = System.nanoTime();

                out.println(MVR_Message);

                Sending_time = System.nanoTime();
                TST[loop_No][6] = Sending_time;
                System.out.println("Message : " + MVR_Message);
                System.out.println("Payload length [bytes]: " + MVR_Payload.getBytes().length);
                System.out.println("Message length [bytes]: " + MVR_Message.getBytes().length);
                System.out.println("Message Sent at " + new Timestamp(System.currentTimeMillis()));

                input = in.readLine();

                if (input.startsWith("ACK_F2")) {
                    exit = true;
                    System.out.println(TEXT_BLUE + "%%%%%%%%%%%%%%%%%%%%%% MESSAGE TO MVR SENT %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n" + TEXT_RESET);
                    VerticalSpace();
                }

            }

            in.close();
            out.close();
            MVR_socket.close();


            System.out.println("%%%%%%%%%%%%%%%%%%%%%% INITIATING MIGRATION SECURITY PROFILE TRANSFER %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");

            //%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   GENERATE MIGRATION MASTER SESSION KEY   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

            VerticalSpace();

            System.out.println("n_s : " + n_s);
            System.out.println("n_r : " + n_r);
            System.out.println("r1' x r2' : " + r1_dash.multiply(r2_dash).toString());

            K_M = Hash_Key(n_s + n_r + (r1_dash.multiply(r2_dash).toString()));

            System.out.println("Generated Migration Session Key [K_M] : " + K_M);

            //Socket Connection Establishment
            R_socket = new Socket(R_IP_Address, R3_PORT);

            in = new BufferedReader(new InputStreamReader(R_socket.getInputStream()));
            out = new PrintWriter(R_socket.getOutputStream(), true);

            System.out.println("gNBs is Connecting to the gNBr................");

            //Sample Security Profile Generation
            ExtractingSecurityProfiles();

            String SecurityProfileArray = null;
            for(int x=0; x < 3; x++){
                for(int y=0; y < 5; y++) {
                    SecurityProfileArray = SecurityProfileArray + "<" + SecurityProfile[x][y];
                }
                SecurityProfileArray = SecurityProfileArray + " ";
            }

            SECRET_KEY = K_M;
            Current_time = System.nanoTime();

            String G_Payload_1 = SecurityProfileArray+"SPLIT"+Current_time;
            String G_EncryptedPayload_1 = AES_Encrypt(G_Payload_1);
            String G_HMAC = Hash(SecurityProfileArray+Current_time);
            String G_Message_1 = "S_MS_INIT"+ " " + G_EncryptedPayload_1 + " " + G_HMAC;
            PET[loop_No][14] = System.nanoTime();

            out.println(G_Message_1);

            Sending_time = System.nanoTime();
            TST[loop_No][7] = Sending_time;
            System.out.println("Message : " + G_Message_1);
            System.out.println("Payload length [bytes]: " + G_Payload_1.getBytes().length);
            System.out.println("Message length [bytes]: " + G_Message_1.getBytes().length);
            System.out.println("Message Sent at " + new Timestamp(System.currentTimeMillis()));

            input = in.readLine();

            Received_time = System.nanoTime();
            TET[loop_No][8] = Received_time;

            System.out.println("Reply from gNBr: " + input + " received at.." + new Timestamp(Received_time));
            String G_Message_2[] = input.split(" ");
            String MIH = G_Message_2[0];

            if (Check_MIH(MIH, "R_MS_REP")) {

                System.out.println(TEXT_GREEN+"The Received MIH matches with the Migration Session Initiation Request....."+TEXT_RESET);

                String G_DecryptedPayload_2 = AES_Decrypt(G_Message_2[1]);
                String G_DecryptedPayloadArray_2[] = G_DecryptedPayload_2.split(" ");

                ReceivedTS = new Long(G_DecryptedPayloadArray_2[1]);
                Delta_TS = CheckTS(ReceivedTS, Received_time);

                System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                if (Delta_TS <= ClockSkew) {

                    System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);
                    String Selected_SPI = G_DecryptedPayloadArray_2[0];
                    System.out.println("Selected Security Profile : "+Selected_SPI);
                    PET[loop_No][15] = System.nanoTime();

                } else {

                    System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                    System.out.println(TEXT_RED + "DISCARD MESSAGE................." + TEXT_RESET);
                }
            } else {
                System.out.println(TEXT_RED+"The Received MIH DOES NOT match with the Serving Migration Request of gNBs....."+TEXT_RESET);
                System.out.println(TEXT_RED+"DISCARD MESSAGE....."+TEXT_RESET);
            }

            VerticalSpace();
            System.out.println(TEXT_GREEN+"%%%%%%%%%%%%%%%%%%%      INITIATING THE MIGRATION        %%%%%%%%%%%%%%%%%%%%%%%%%%%"+TEXT_RESET);

            VerticalSpace();
            Entity_End_time = System.nanoTime();

            System.out.println("Loop Number : "+loop_No);
            loop_No++;

            System.out.println("The time taken for the gNBs Operation [ms] : " + CheckTS(Entity_Start_time, Entity_End_time));

            VerticalSpace();

            //Gaining the INPUT to MAINTAIN the LOOP
            int lo = 0;
            while(lo == 0) {
                System.out.println(TEXT_PURPLE+"Do you wish to continue the PROTOCOL [Y/N] : "+TEXT_RESET);
                String Res = Sc.nextLine();
                System.out.println("Entered Response : "+Res);

                if (Res.startsWith("YES") || Res.startsWith("yes")) {
                    loop = true;
                    lo = 1;
                } else if (Res.startsWith("NO") || Res.startsWith("no")) {
                    loop = false;
                    lo = 1;
                } else {
                    System.out.println(TEXT_RED + "INVALID INPUT..........." + TEXT_RESET);
                    lo = 0;
                }
            }

            System.out.println("Displaying the Timing Values................\n\n\n");

            System.out.println("EST : ");
            for(int x = 0; x < loop_No; x++){

                System.out.print(", "+EST[x]);
            }
            System.out.println();

            System.out.println("TET : ");
            for(int x = 0; x < loop_No; x++){

                for(int y = 0; y < 9; y++){
                    System.out.print(", "+TET[x][y]);
                }
                System.out.print("; \n");
            }

            System.out.println();

            System.out.println("TST : ");
            for(int x = 0; x < loop_No; x++){

                for(int y = 0; y < 8; y++){
                    System.out.print(", "+TST[x][y]);
                }
                System.out.print("; \n");
            }
            System.out.println();

            System.out.println("PET : ");
            for(int x = 0; x < loop_No; x++){

                for(int y = 0; y < 16; y++){
                    System.out.print(", "+PET[x][y]);
                }
                System.out.println("; \n");
            }

            long EPD_1 = 0;
            long DPD_1 = 0;
            long EPD_2 = 0;

            for(int x = 0; x < loop_No; x++){

               EPD_1 = EPD_1 + (PET[x][0] - EST[x]);
            }

            EPD_1 = EPD_1/loop_No;

            for(int x = 0; x < loop_No; x++){

                DPD_1 = DPD_1 + (PET[x][1] - TET[x][0]);
            }

            DPD_1 = DPD_1/loop_No;


            System.out.println("Average EPD 1 [ms]: "+(EPD_1/1000000));
            System.out.println("Average DPD 1 [ms]: "+(DPD_1/1000000));


        }

    }



    public static void main(String[] args) throws UnknownHostException, Exception {

        System.out.println("Source gNB MEC Server is Running at "+getCurrentTimestamp());

        Source_gNB gNBs = new Source_gNB();



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

    private void startListening_TTP_R(int port)throws IOException {
        listener = CreateListeningSocket(port);
        //acceptedSocket = es.submit( new ServAccept( listener ) );
        Socket serverSocket = listener.accept();

        BufferedReader in = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
        PrintWriter out = new PrintWriter(serverSocket.getOutputStream(), true);

        exit = false;

        try {

            while(exit == false) {

                input = in.readLine();
                Received_time = System.nanoTime();
                TET[loop_No][5] = Received_time;
                System.out.println("Message from TTP: " + input + " received at.." + new Timestamp(Received_time));
                String TTP_Message_5[] = input.split(" ");
                String MIH = TTP_Message_5[0];
                String TTP_EncryptedPayload_5 = TTP_Message_5[1];
                System.out.println("Encrypted Payload : " + TTP_EncryptedPayload_5);
                String TTP_DecryptedPayload_5 = RSA_decrypt(TTP_EncryptedPayload_5, privateKey_gNBs);
                System.out.println("Decrypted Payload : " + TTP_DecryptedPayload_5);
                String[] TTP_DecryptedPayloadArray_5 = TTP_DecryptedPayload_5.split(" ");

                ReceivedTS = new Long(TTP_DecryptedPayloadArray_5[4]);
                Delta_TS = CheckTS(ReceivedTS, Received_time);

                System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                if (Delta_TS <= ClockSkew) {
                    System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);

                    if (Check_MIH(MIH, "TTP_SV_VER")) {
                        System.out.println(TEXT_GREEN+"MIHs are matching in the Received Message..............."+TEXT_RESET);

                        String Received_TTP_ID = TTP_DecryptedPayloadArray_5[0];
                        String Received_MP_ID = TTP_DecryptedPayloadArray_5[1];

                        if (Received_TTP_ID.equals(TTP_ID)) {
                            System.out.println(TEXT_GREEN+"TTP ID Verified and Recorded..............."+TEXT_RESET);

                            if (Received_MP_ID.equals(MP_IDs[0])) {
                                System.out.println(TEXT_GREEN+"MP ID Verified and Recorded..............."+TEXT_RESET);

                                PC2 = TTP_DecryptedPayloadArray_5[2];
                                SECRET_KEY = Create_ECDH_SecretKey(PC2,PC1,kpC1);

                                String TTP_DecryptedSecretPayload_5 = AES_Decrypt(TTP_DecryptedPayloadArray_5[3]);
                                String[] TTP_DecryptedSecretPayloadArray_5 = TTP_DecryptedSecretPayload_5.split(" ");

                                M_CODE = TTP_DecryptedSecretPayloadArray_5[0];
                                r2_dash = new BigInteger(TTP_DecryptedSecretPayloadArray_5[1]);

                                System.out.println("Received M CODE : "+M_CODE);
                                System.out.println(TEXT_GREEN+"M CODE is linked to the MP ID..............."+TEXT_RESET);

                                out.println("ACK_D2");

                                exit = true;
                                VerticalSpace();
                                System.out.println("%%%%%%%%%%%%%%%%%%%%%% FINAL MESSAGE FROM TTP COMPLETED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                                System.out.println("%%%%%%%%%%%%%%%%%%%%%%  The PROTOCOL SEGMENT D between gNBs and TTP SERVER is Complete %%%%%%%%%%%%%%%%%%%\n\n");
                                PET[loop_No][9] = System.nanoTime();
                                VerticalSpace();
                            } else {
                                System.out.println(TEXT_RED+"MP ID Does NOT EXIST  ==> Possible Tampering"+TEXT_RESET);
                                out.println("RETRANSMIT_D2");
                            }
                        } else {
                            System.out.println(TEXT_RED+"TTP ID Does NOT EXIST  ==> Possible Tampering"+TEXT_RESET);
                            out.println("RETRANSMIT_D2");
                        }
                    } else System.out.println(TEXT_RED+"MIHs Does not match..............."+TEXT_RESET);
                } else {
                    System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                    System.out.println(TEXT_RED + "DISCARD MESSAGE................." + TEXT_RESET);
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
                System.out.println("TTP Connection to gNBs...Stopped");
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }
    }

    private void startListening_R(int port)throws IOException {
        listener = CreateListeningSocket(port);
        //acceptedSocket = es.submit( new ServAccept( listener ) );
        Socket serverSocket = listener.accept();

        BufferedReader in = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
        PrintWriter out = new PrintWriter(serverSocket.getOutputStream(), true);

        //BufferedReader in = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
        //PrintWriter out = new PrintWriter(new OutputStreamWriter(serverSocket.getOutputStream()));

        System.out.println("gNBs Listener Running for gNBr..................");

        SignatureFailCount = 0;
        NonceVerifierCount = 0;
        ProtocolMsgCount = 0;
        exit = false;

        try {

            while(exit == false) {

                if(ProtocolMsgCount % 2 == 0){
                    input = in.readLine();
                }

                if(ProtocolMsgCount == 0) {

                    Received_time = System.nanoTime();
                    TET[loop_No][6] = Received_time;
                    System.out.println("Message from Roaming gNB: " + input + " received at.." + new Timestamp(Received_time));
                    String R_Message_1[] = input.split(" ");
                    String R_EncryptedPayload_1 = R_Message_1[1];
                    System.out.println("Encrypted Payload : " + R_EncryptedPayload_1);
                    String R_DecryptedPayload_1 = RSA_decrypt(R_EncryptedPayload_1, privateKey_gNBs);
                    System.out.println("Decrypted Payload : " + R_DecryptedPayload_1);
                    String[] R_DecryptedPayloadArray_1 = R_DecryptedPayload_1.split(" ");

                    ReceivedTS = new Long(R_DecryptedPayloadArray_1[5]);

                    Delta_TS = CheckTS(ReceivedTS, Received_time);
                    System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

                    if (Delta_TS <= ClockSkew) {

                        System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);
                        String R_VerifyingSignature_1 = Hash(S_ID + " " + ReceivedTS);

                        if (RSA_verify(R_VerifyingSignature_1, R_Message_1[2], publicKey_gNBr)) {
                            System.out.println(TEXT_GREEN + "Signatures are Matching..............." + TEXT_RESET);

                            //Nonce Verifier for gNBr
                            if (R_DecryptedPayloadArray_1[4].equals(Hash128(n_s + ReceivedTS))) {

                                if (R_ID.equals(R_DecryptedPayloadArray_1[0])) {

                                    System.out.println("Migration Registration for " + R_ID + " is underway..........");

                                    if (MP_IDs[0].equals(R_DecryptedPayloadArray_1[1])) {

                                        System.out.println("MP ID Check Verified for ID : " + MP_IDs[0]);

                                        PC3 = R_DecryptedPayloadArray_1[2];
                                        SECRET_KEY = Create_ECDH_SecretKey(PC3,PC1,kpC1);

                                        String R_DecryptedSecretPayload_1 = AES_Decrypt(R_DecryptedPayloadArray_1[3]);
                                        String[] R_DecryptedSecretPayloadArray_1 = R_DecryptedSecretPayload_1.split(" ");

                                        String Received_R_M_CODE = R_DecryptedSecretPayloadArray_1[0];
                                        n_r = R_DecryptedSecretPayloadArray_1[1];

                                        //MATCHING M_CODES
                                        if (CheckHash(Received_R_M_CODE, M_CODE)) {

                                            System.out.println(TEXT_GREEN+"The M_CODEs are MATCHING >>>>>>>>>>>>>>>>   Mutual Authentication Established with gNBr"+TEXT_RESET);
                                            VerticalSpace();
                                            ProtocolMsgCount = 1;
                                            System.out.println("%%%%%%%%%%%%%%%%%%%%%% C and D Segements of the Protocol Concluded %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");
                                            PET[loop_No][10] = System.nanoTime();

                                            VerticalSpace();

                                        } else System.out.println(TEXT_RED+"The M_CODEs are NOT MATCHING  >>>>>>>>>>>>>>>>  NOT Authenticated"+TEXT_RESET);

                                    } else System.out.println("MP IDs are NOT MATCHING..............");
                                } else System.out.println("R_ID is NOT MATCHING..............");
                            } else {
                                System.out.println(TEXT_RED+"R Nonce is NOT Verified..............."+TEXT_RESET);
                                System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED.........................." + TEXT_RESET);

                                out.println("RETRANSMIT_C1");

                                NonceVerifierCount++;
                                if (NonceVerifierCount == 3) exit(0);
                            }
                        } else {
                            System.out.println(TEXT_RED + "Signatures Does not match..............." + TEXT_RESET);
                            System.out.println(TEXT_RED + "RETRANSMISSION REQUESTED..............." + TEXT_RESET);

                            out.println("RETRANSMIT_C1");

                            SignatureFailCount++;
                            if (SignatureFailCount == 3) exit(0);
                        }
                    } else {

                        System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                        System.out.println(TEXT_RED + "MESSAGE DISCARDED................." + TEXT_RESET);
                        exit(0);

                    }

                    //////////////////////////////////////  SEGMENT E /////////////////////////////////////////////////////////////////////////////

                    ///////////////////////////////////// Message 1  //////////////////////////////////////////////////////////////////////////////

                } else  if((ProtocolMsgCount == 1)||(input.startsWith("RETRANSMIT_E0"))) {

                    MES_ID = RandomNonceGenerator();
                    Double MES_CPU = 55.8;
                    Double MES_RAM = 63.5;
                    Double MES_STORAGE = 2.25; //GB
                    String MES_STATE = "<"+MES_CPU+"><"+MES_RAM+"><"+MES_STORAGE;
                    String MES_DATA = "<00012><AV_Control><AB002546><Linux><253.0.152.14><80>"; //<MES_ID><MES_Name><ID_Container><OS_Container><IP_MES_Main_Server><MES_QCI>
                    String MES_REQ = "<2GHz><2GB><2GB><1Mbps>"; //<CPU><RAM><HDD><BW>

                    PE1 = Generate_ECDH_SharingKey_E1(ECDH_Key_Length_3);

                    Current_time = System.nanoTime();
                    String R_Payload_2 = MP_IDs[0] + " " + MES_ID + " " + MES_STATE + " " + MES_DATA + " " + MES_REQ + " " + MVR_ID + " " + PE1 + " " + Current_time;
                    System.out.println("Payload : " + R_Payload_2);

                    String R_HMAC_2 = Hash(MP_IDs[0] + MES_ID + MES_STATE + MES_DATA + MES_REQ + MVR_ID + PE1 + Current_time);
                    byte[] R_EncryptedPayloadBytes_2 = RSA_encrypt(R_Payload_2, publicKey_gNBr);
                    String R_EncryptedPayload_2 = Base64.getEncoder().encodeToString(R_EncryptedPayloadBytes_2);
                    System.out.println("Encrypted Payload 1 : " + R_EncryptedPayload_2);
                    String R_Message_2 = "S_MES_REQ" + " " + R_EncryptedPayload_2 + " " + R_HMAC_2;
                    PET[loop_No][11] = System.nanoTime();

                    out.println(R_Message_2);

                    Sending_time = System.nanoTime();
                    TST[loop_No][5] = Sending_time;
                    System.out.println("Message 1 : " + R_Message_2);
                    System.out.println("Hash length [bytes]: " + R_HMAC_2.getBytes().length);
                    System.out.println("Payload 1 length [bytes]: " + R_Payload_2.getBytes().length);
                    System.out.println("Message 1 length [bytes]: " + R_Message_2.getBytes().length);
                    System.out.println("Message 1 to gNBr Sent at " + new Timestamp(Sending_time));
                    ProtocolMsgCount = 2;
                    VerticalSpace();

                }else if (input.startsWith("ACK_E0")) {
                    System.out.println("Message with MES information forwarded to Romaing gNB................");
                    exit = true;
                    VerticalSpace();

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
                System.out.println("Listener 1 towards gNBr Connection...Stopped");
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }
    }

    private void startListening_R1(int port)throws IOException {
        listener = CreateListeningSocket(port);
        //acceptedSocket = es.submit( new ServAccept( listener ) );
        Socket serverSocket = listener.accept();

        BufferedReader in = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
        PrintWriter out = new PrintWriter(serverSocket.getOutputStream(), true);

        //BufferedReader in = new BufferedReader(new InputStreamReader(serverSocket.getInputStream()));
        //PrintWriter out = new PrintWriter(new OutputStreamWriter(serverSocket.getOutputStream()));

        System.out.println("gNBs Listener Running for gNBr for the Second Time..................");

        try {

            ////////////////////////////////////////    RECEIVING MES MESSAGE FROM gNBr /////////////////////////////////////////////////////

            String input = in.readLine();
            Received_time = System.nanoTime();
            TET[loop_No][7] = Received_time;

            System.out.println("Message from Roaming gNB: "+input+" received at.."+new Timestamp(System.currentTimeMillis()));
            String R_Message_MES[] = input.split(" ");
            String R_EncryptedPayload_MES = R_Message_MES[1];
            System.out.println("Encrypted Payload : "+R_EncryptedPayload_MES);
            String R_DecryptedPayload_MES = RSA_decrypt(R_EncryptedPayload_MES,privateKey_gNBs);
            System.out.println("Decrypted Payload : "+R_DecryptedPayload_MES);
            String[] R_DecryptedPayloadArray_MES = R_DecryptedPayload_MES.split(" ");

            Long ReceivedTS = new Long(R_DecryptedPayloadArray_MES[4]);

            Delta_TS = CheckTS(ReceivedTS, Received_time);

            System.out.println("TS Difference [ms] : " + Delta_TS);  // Figuring out whether there has been a Replay Attack

            if (Delta_TS <= ClockSkew) {

                System.out.println(TEXT_GREEN + "The Received Message is FRESH................." + TEXT_RESET);

                if(R_ID.equals(R_DecryptedPayloadArray_MES[0])){
                    System.out.println(TEXT_GREEN+"MVR IDs are matching in the Received Message..............."+TEXT_RESET);

                    PF1 = R_DecryptedPayloadArray_MES[1];
                    PF2 = R_DecryptedPayloadArray_MES[2];
                    SECRET_KEY = Create_ECDH_SecretKey(PF1,PE1,kpE1);

                    String R_DecryptedSecretPayload_MES = AES_Decrypt(R_DecryptedPayloadArray_MES[3]);
                    String[] R_DecryptedSecretPayloadArray_MES = R_DecryptedSecretPayload_MES.split(" ");

                    MES_RES = new Boolean(R_DecryptedSecretPayloadArray_MES[0]);
                    MES_CODE = R_DecryptedSecretPayloadArray_MES[1];

                    if(MES_RES == true){

                        System.out.println(TEXT_GREEN+"MES Resource Verification Done ==> MES can be Migrated................"+TEXT_RESET);
                        PET[loop_No][12] = System.nanoTime();

                    }else System.out.println(TEXT_RED+"MES Resource Verification Failure.............."+TEXT_RESET);

                } else System.out.println(TEXT_RED+"MVR ID Does not match..............."+TEXT_RESET);

            } else {

                System.out.println(TEXT_RED + "The Received Message is NOT FRESH ==> REPLAY ATTEMPT................." + TEXT_RESET);
                System.out.println(TEXT_RED + "DISCARD MESSAGE................." + TEXT_RESET);
            }

            VerticalSpace();

            System.out.println("%%%%%%%%%%%%%%%%%%%%%% MES_RES and MES_CODE Received Successfully from gNBr %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n\n");

            VerticalSpace();

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // Clean up
            try {
                in.close();
                out.close();
                serverSocket.close();
                listener.close();
                System.out.println("Second Listener towards the gNBr Connection...Stopped");
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

    public static Timestamp getCurrentTS(){
        return new Timestamp(System.nanoTime());
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

    public void ExtractingSecurityProfiles(){

        for(int x=0; x < 3; x++){
            for(int y=0; y < 5; y++){
                SecurityProfile[x][y] = new ArrayList<>();
            }
        }
        SecurityProfile[0][0].add("0001");
        SecurityProfile[0][1].add("TUNNEL");
        SecurityProfile[0][2].add("IPSec");
        SecurityProfile[0][3].add("NIL");
        SecurityProfile[0][4].add("NIL");

        SecurityProfile[1][0].add("0002");
        SecurityProfile[1][1].add("NO");
        SecurityProfile[1][2].add("AES");
        SecurityProfile[1][3].add("512");
        SecurityProfile[1][4].add("TS");

        SecurityProfile[2][0].add("0003");
        SecurityProfile[2][1].add("NO");
        SecurityProfile[2][2].add("ECC");
        SecurityProfile[2][3].add("256");
        SecurityProfile[2][4].add("HMAC-256");
    }

    /////////////////////////////////   HASHING FUNCTIONS   //////////////////////////////////////

    public boolean CheckHash(String CheckingHash, String TargetHash){

        return CheckingHash.matches(TargetHash);
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
                System.out.println(".................The DoS Puzzle is VERIFIED..............\n\n");
            }else {

                System.out.println(".............The DoS Puzzle is Not Verified ==> DoS Attack Detected..........\n\n");
            }

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

        privateKey_gNBs = privateKey;

        String stringPublicKey = new String(Files.readAllBytes(Paths.get(Certificate_Path+"PUBLIC_KEY_"+Entity_Name+".txt")));

        System.out.println("Loaded String Public Key : "+stringPublicKey);

        byte[] decodedPublicKey = Base64.getDecoder().decode(stringPublicKey);

        KeySpec keySpecPublic = new X509EncodedKeySpec(decodedPublicKey);

        PublicKey publicKey = kf.generatePublic(keySpecPublic);

        publicKey_gNBs = publicKey;

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

    /*
    //@@@@@@@@@@@@@@@@@@@@@@@@  RSA Encryption Algorithm @@@@@@@@@@@@@@@@@@@@@@

    //Function for computing RSA public parameters for the OSS CA
    public static void RSA(){
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(RSA_bit_length,100,r);
        BigInteger q = new BigInteger(RSA_bit_length,100,r);
        N_s = p.multiply(q);
        BigInteger n =
                (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e_s = new BigInteger("3");
        while(n.gcd(e_s).intValue()>1){
            e_s = e_s.add(new BigInteger("2"));
        }
        d_s = e_s.modInverse(n);
    }
    //Function for RSA Encrypting
    public static BigInteger RSAencrypt (BigInteger message, BigInteger ex, BigInteger Nx){
        return message.modPow(ex, Nx);
    }
    //Function for RSA Decryption
    public static BigInteger RSAdecrypt (BigInteger message, BigInteger dx, BigInteger Nx){
        return message.modPow(dx, Nx);
    }

    //Function for RSA Signing
    public static BigInteger RSAsign (BigInteger message, BigInteger dx, BigInteger Nx){
        return message.modPow(dx, Nx);
    }
    //Function for RSA Un-signing
    public static BigInteger RSAunsign (BigInteger message, BigInteger ex, BigInteger Nx){
        return message.modPow(ex, Nx);
    }
    */

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

    //@@@@@@@@@@@Advanced Encryption Standard (AES) @@@@@@@@@@@@@@@@@@@@@@

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

    public static String Generate_ECDH_SharingKey_A(int Key_Size)throws NoSuchAlgorithmException{
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(Key_Size);
        kpA = kpg.generateKeyPair();
        byte[] SharingKey = kpA.getPublic().getEncoded();

        String SK = encodeHexString(SharingKey);
        System.out.println("Sharing Key: "+SK);
        return SK;
    }

    public static String Generate_ECDH_SharingKey_B(int Key_Size)throws NoSuchAlgorithmException{
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(Key_Size);
        kpB = kpg.generateKeyPair();
        byte[] SharingKey = kpB.getPublic().getEncoded();

        String SK = encodeHexString(SharingKey);
        System.out.println("Sharing Key: "+SK);
        return SK;
    }

    public static String Generate_ECDH_SharingKey_C1(int Key_Size)throws NoSuchAlgorithmException{
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(Key_Size);
        kpC1 = kpg.generateKeyPair();
        byte[] SharingKey = kpC1.getPublic().getEncoded();

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

    public static String Generate_ECDH_SharingKey_E2(int Key_Size)throws NoSuchAlgorithmException{
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(Key_Size);
        kpE2 = kpg.generateKeyPair();
        byte[] SharingKey = kpE2.getPublic().getEncoded();

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


