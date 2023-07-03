package app.utilities;

import org.bouncycastle.jce.provider.BrokenPBE;

import javax.crypto.Cipher;
import java.io.*;
import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.*;

public class MainFunc {
    // Kreirati folder Rpeozitorijum
    // sadrzi do 10 foldera
    // Enkripcija javnim kljucem
    // Podjela fajl na 4 do 10 dijelova i smjestanje u direktorijume [1 - N]
    // Format je filename_username.ext
    // Sastavljanje pa dekripcija
    // Nakon stavljanja svaki fajl hesirati i cuvati hes
    // Kada se korisnik loguje Ponovo se hesiraju njegovi fajlovi i poredi se sa starim hesevima
    // Ako se neki hes ne poklapa, prikazati poruku korisniku {"Detektovane izmjene u fajlu filename.ext}
    public static String REPOSITORY = "src" + File.separator + "main" + File.separator + "java" + File.separator + "repository";
    public static String INFO_FILE = REPOSITORY + File.separator + "info_file";

    public static void encryptFile(File file, String username) throws Exception{

        KeyPair keyPair = Utilities.readKeyPair(username);
        FileInputStream fileInputStream = new FileInputStream(file);
        BufferedInputStream bis = new BufferedInputStream(fileInputStream);
        int length = (int) file.length();
        Random rand = new Random();
        int n = rand.nextInt(4,10);
        int subfileLen = length / n;
        int remainder = length % n;
        byte[] buffer = new byte[subfileLen];
        byte[] remainderBuff = new byte[remainder];
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        int bytesRead = 0;
        int i = 0;
        Path pathToFile = file.toPath();
        String[] split = pathToFile.getFileName().toString().split("\\.");
        String filename = split[0];
        while(((bytesRead = fileInputStream.read(buffer)) != -1)) {
            byte[] outputBytes = cipher.doFinal(buffer);
            FileOutputStream fos = new FileOutputStream(REPOSITORY + File.separator + i + File.separator + filename + "_" + username);
            FileOutputStream digestFile = new FileOutputStream(REPOSITORY + File.separator + i + File.separator + filename + "_" + username + "_digest");
            String fileDigest = Cryptography.digestFile(outputBytes);
            // Enkriptovati prvo bi bilo pozeljno
            digestFile.write(fileDigest.getBytes(StandardCharsets.UTF_8));
            digestFile.close();
            // Potrebno pronaci hash i upisati
            fos.write(outputBytes);
            fos.close();
            i++;
            if(i == n){
                break;
            }
        }
        fileInputStream.read(remainderBuff);
        byte[] outputBytes = cipher.doFinal(remainderBuff);
        FileOutputStream fos = new FileOutputStream(REPOSITORY + File.separator + i + File.separator + filename + "_" + username);

        // Potrebno pronaci hash i upisati
        fos.write(outputBytes);
        fos.close();
        fileInputStream.close();
       String newInfo = username + ";" + filename + ";" + n;
        try (FileWriter writer = new FileWriter(INFO_FILE, true)) {
            writer.write(newInfo + System.lineSeparator());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static ArrayList<String> changedFiles(String username) {
        // vratiti listu izmijenjenih fajlova
        // prikazati korisniku
        ArrayList<String> changedFilesList = new ArrayList<>();
        try {
            Path infoFile = Paths.get(INFO_FILE);
            ArrayList<String> userFiles = new ArrayList<>();

            ArrayList<Integer> numOfDivisions = new ArrayList<>();
            List<String> lines = Files.readAllLines(infoFile);
            for (String line:lines) {
                String[] infoSplit = line.split(";");
                if(username.equals(infoSplit[0])) {
                userFiles.add(infoSplit[1]);
                numOfDivisions.add(Integer.parseInt(infoSplit[2]));
                }
            }

            for(String filename : userFiles) {
                System.out.println(filename);
                int j  = 0;
                for(int i  =0 ; i < numOfDivisions.get(0); i++) {

                   String savedHash = new String(Files.readAllBytes(Paths.get(REPOSITORY + File.separator + i  + File.separator  + filename + "_" + username + "_digest")));
                    String currentHash = Cryptography.digestFile(Files.readAllBytes(Paths.get(REPOSITORY + File.separator + i  + File.separator  + filename + "_" + username)));
                    System.out.println(savedHash);
                    System.out.println(currentHash);
                    if (!savedHash.equals(currentHash)) {
                        changedFilesList.add(filename);
                        break;
                    }
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
        return changedFilesList;
    }

    public static void decryptFile(String filename, String username) throws Exception {
        // dekriptuje fajl (sloziti prije toga)
        KeyPair keyPair = Utilities.readKeyPair(username);
        int n = 0; // DOHVATI N iz fajla
        List<String> lines = Files.readAllLines(Paths.get(INFO_FILE));
        for (String line : lines) {
            String[] infoSplit = line.split(";");

            if (username.equals(infoSplit[0]) && filename.equals(infoSplit[1])) {
                n = Integer.parseInt(infoSplit[2]);
            }

        }
        MainFunc.removeLine(username, filename, n);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        for (int i = 0; i <= n; i++) { // Promijeniti uslov

            File file = new File(REPOSITORY + File.separator + i + File.separator + filename + "_" + username);
            File digestFile = new File(REPOSITORY + File.separator + i + File.separator + filename + "_" + username +"_digest");
            FileInputStream fileInputStream = new FileInputStream(file);
            byte[] buffer = new byte[(int) file.length()];
            int bytesRead = 0;
            fileInputStream.read(buffer);
            byte[] outputBytes = cipher.doFinal(buffer);

            FileOutputStream fos = new FileOutputStream(Utilities.USER_IO + File.separator + username +File.separator + filename +  "_decrypted.txt", true);
            fos.write(outputBytes);
            fos.flush();
            fos.close();
            fileInputStream.close();
            if(file.delete())
                System.out.println("OBRISAN");
            if(digestFile.delete())
                System.out.println("OBRISAN DIGEST");
        }
    }

        public static boolean existsInRepo(File file) throws IOException {
            Path pathToFile = file.toPath();
            String[] split = pathToFile.getFileName().toString().split("\\.");
            String filename = split[0];
            String username = Utilities.getCurrentUser();
            System.out.println(username);
            System.out.println(filename);
            List<String> lines = Files.readAllLines(Paths.get(INFO_FILE));
            for (String line : lines) {
                String[] infoSplit = line.split(";");

                if (username.equals(infoSplit[0]) && filename.equals(infoSplit[1])) {
                    return true;
                }
            }
            return false;
        }

        public static ArrayList<String> listCurrentUserFiles(String username){
            ArrayList<String> currentFiles = new ArrayList<>();
            try {
                List<String> lines = Files.readAllLines(Paths.get(INFO_FILE));
                for (String line : lines) {
                    String[] infoSplit = line.split(";");

                    if (username.equals(infoSplit[0])) {
                        currentFiles.add(infoSplit[1]);
                    }
                }
            } catch (IOException e){
                System.out.println("PROBLEM LISTING FILES");
            }
            return currentFiles;
        }

        public static void removeLine(String username, String filename, int  n) {
            ArrayList<String> lines = new ArrayList<>();
            Scanner scanner = null;
            try {
                scanner = new Scanner(new File(INFO_FILE));
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine();
                    if (!line.equals(username + ";" + filename + ";" + n)) {
                        lines.add(line);
                    }
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } finally {
                if (scanner != null) {
                    scanner.close();
                }
            }

            PrintWriter writer = null;
            try {
                writer = new PrintWriter(INFO_FILE);
                for (String line : lines) {
                    writer.println(line);
                }
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } finally {
                if (writer != null) {
                    writer.close();
                }
            }
        }
}
