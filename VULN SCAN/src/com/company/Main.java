package com.company;

import org.apache.commons.io.FileUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class Main {

    static void sqlInjectionScanner(List<File> phpFiles)
    {
        int numofVul=0;
        String Scanned = null;
        for (File phpFile : phpFiles) {
            try {
                 Scanned = "";
                System.out.println("Vulnerabilities found in " + phpFile.getAbsolutePath() + ":");
                FileReader fileReader = new FileReader(phpFile);
                BufferedReader bufferedReader = new BufferedReader(fileReader);
                String line;
                //patternssssssssssssssssssssssssssssss

                Pattern pattern1 = Pattern.compile("\\$\\w+\\s*=\\s*\\$_(GET|POST)\\[.*\\];");
                Pattern pattern2 = Pattern.compile("\\$\\w+\\s*=\\s*mysql_query\\(.*\\);");
                Pattern pattern3 = Pattern.compile("\\$\\w+\\s*=\\s*mysqli_query\\(.*\\);");
                Pattern pattern4 = Pattern.compile("\\$\\w+\\s*=\\s*pg_query\\(.*\\);");
                Pattern pattern5 = Pattern.compile("\\$\\w+\\s*=\\s*sqlite_query\\(.*\\);");
                Pattern pattern6 = Pattern.compile("mysql_query\\(.*\\$\\w+.*\\);");
                Pattern pattern7 = Pattern.compile("mysqli_query\\(.*\\$\\w+.*\\);");
                Pattern pattern8 = Pattern.compile("pg_query\\(.*\\$\\w+.*\\);");
                Pattern pattern9 = Pattern.compile("sqlite_query\\(.*\\$\\w+.*\\);");
                Pattern pattern10 = Pattern.compile("mysql_query\\(\\$\\w+.*\\);");
                Pattern pattern11 = Pattern.compile("mysqli_query\\(\\$\\w+.*\\);");
                Pattern pattern12 = Pattern.compile("pg_query\\(\\$\\w+.*\\);");
                Pattern pattern13 = Pattern.compile("sqlite_query\\(\\$\\w+.*\\);");
                Pattern pattern14 = Pattern.compile("SELECT\\s.*\\sFROM\\s.*\\sWHERE\\s.*;");
                Pattern pattern15 = Pattern.compile("UPDATE\\s.*\\sSET\\s.*\\sWHERE\\s.*;");
                Pattern pattern16 = Pattern.compile("DELETE\\sFROM\\s.*\\sWHERE\\s.*;");
                Pattern pattern17 = Pattern.compile("INSERT\\sINTO\\s.*\\(.*\\)\\sVALUES\\(.*\\);");
                Pattern pattern18 = Pattern.compile("OR\\s.*=\\s.*");
                boolean foundVulnerability = false;
                int lineNumber = 1;
                while ((line = bufferedReader.readLine()) != null) {
                    Matcher matcher1 = pattern1.matcher(line);
                    Matcher matcher2 = pattern2.matcher(line);
                    Matcher matcher3 = pattern3.matcher(line);
                    Matcher matcher4 = pattern4.matcher(line);
                    Matcher matcher5 = pattern5.matcher(line);
                    Matcher matcher6 = pattern6.matcher(line);
                    Matcher matcher7 = pattern7.matcher(line);
                    Matcher matcher8 = pattern8.matcher(line);
                    Matcher matcher9 = pattern9.matcher(line);
                    Matcher matcher10 = pattern10.matcher(line);
                    Matcher matcher11 = pattern11.matcher(line);
                    Matcher matcher12 = pattern12.matcher(line);
                    Matcher matcher13 = pattern13.matcher(line);
                    Matcher matcher14 = pattern14.matcher(line);
                    Matcher matcher15 = pattern15.matcher(line);
                    Matcher matcher16 = pattern16.matcher(line);
                    Matcher matcher17 = pattern17.matcher(line);
                    Matcher matcher18 = pattern18.matcher(line);
                    if (matcher1.find() || matcher2.find() || matcher3.find() || matcher4.find() || matcher5.find() || matcher6.find() || matcher7.find() || matcher8.find() || matcher9.find() || matcher10.find() || matcher11.find() || matcher12.find() || matcher13.find() || matcher14.find() || matcher15.find() || matcher16.find() || matcher17.find() || matcher18.find()) {
                        System.out.println("Possible SQL injection vulnerability found in line: "+lineNumber+" :" + line);
                        //Scanned="Possible SQL injection vulnerability found in line: " +lineNumber+" :"+ line;
                        numofVul++;

                        foundVulnerability = true;
                       // break;
                    }

                    lineNumber++;
                }
                if (!foundVulnerability) {
                    System.out.println("No SQL injection vulnerabilities found in this file.");
                }

                bufferedReader.close();
                fileReader.close();
            } catch (IOException e) {
                System.err.println("Error reading " + phpFile.getAbsolutePath() + ": " + e.getMessage());
            }
            System.out.println("---------------------------------------------------------------");
            System.out.println("---------------------------------------------------------------");
        }
        System.out.println("Total Numbers SQL of INJECTION Vulnerabilities = " + numofVul);
       // return Scanned;
    }

    //XSSssssssssssssssssssssssssssssssssssss




    static void xssScanner(List<File> phpFiles)
    {
        int numofVul=0;
        String Scanned = null;
        for (File phpFile : phpFiles) {
            try {
                Scanned = "";
                System.out.println("Vulnerabilities found in " + phpFile.getAbsolutePath() + ":");
                FileReader fileReader = new FileReader(phpFile);
                BufferedReader bufferedReader = new BufferedReader(fileReader);
                String line;
                //patternssssssssssssssssssssssssssssss

                Pattern pattern1 = Pattern.compile("echo\\s*\\$_(GET|POST|REQUEST)\\[.*\\];");
                Pattern pattern2 = Pattern.compile("print\\s*\\$_(GET|POST|REQUEST)\\[.*\\];");
                Pattern pattern3 = Pattern.compile("echo\\s*\\$\\w+\\s*;.*\\$_(GET|POST|REQUEST)\\[.*\\];");
                Pattern pattern4 = Pattern.compile("print\\s*\\$\\w+\\s*;.*\\$_(GET|POST|REQUEST)\\[.*\\];");
                Pattern pattern5 = Pattern.compile("echo\\s*\\$\\w+\\s*;.*htmlspecialchars\\(.*\\);");
                Pattern pattern6 = Pattern.compile("print\\s*\\$\\w+\\s*;.*htmlspecialchars\\(.*\\);");
                Pattern pattern7 = Pattern.compile("echo\\s*\\$\\w+\\s*;.*\\$_(GET|POST|REQUEST)\\[.*\\];.*\\?>");
                Pattern pattern8 = Pattern.compile("print\\s*\\$\\w+\\s*;.*\\$_(GET|POST|REQUEST)\\[.*\\];.*\\?>");
                Pattern pattern9 = Pattern.compile("echo\\s*htmlspecialchars\\(.*\\);.*\\$_(GET|POST|REQUEST)\\[.*\\];.*\\?>");
                Pattern pattern10 = Pattern.compile("print\\s*htmlspecialchars\\(.*\\);.*\\$_(GET|POST|REQUEST)\\[.*\\];.*\\?>");
                Pattern pattern11 = Pattern.compile("echo\\s*\\$\\w+\\s*;.*htmlspecialchars\\(.*\\);.*\\?>");
                Pattern pattern12 = Pattern.compile("print\\s*\\$\\w+\\s*;.*htmlspecialchars\\(.*\\);.*\\?>");
                Pattern pattern13 = Pattern.compile("echo\\s*\\$_(GET|POST|REQUEST)\\[.*\\].*htmlspecialchars\\(.*\\);.*\\?>");
                Pattern pattern14 = Pattern.compile("print\\s*\\$_(GET|POST|REQUEST)\\[.*\\].*htmlspecialchars\\(.*\\);.*\\?>");
                Pattern pattern15 = Pattern.compile("echo\\s*\\$\\w+\\s*;.*\\$_(GET|POST|REQUEST)\\[.*\\];.*htmlspecialchars\\(.*\\);.*\\?>");
                Pattern pattern16 = Pattern.compile("print\\s*\\$\\w+\\s*;.*\\$_(GET|POST|REQUEST)\\[.*\\];.*htmlspecialchars\\(.*\\);.*\\?>");
                Pattern pattern17 = Pattern.compile("<script.*>.*</script>");
                Pattern pattern18 = Pattern.compile("<script\\s*src\\s*=\\s*[\"\'].*[\"\']\\s*>");
                Pattern pattern19 = Pattern.compile("<img\\s*src\\s*=\\s*[\"\']javascript:.*[\"\']\\s*>");
                Pattern pattern20 = Pattern.compile(".*\\$\\w+\\s*=\\s*\\$\\w+.*<script>.*</script>.*");
                Pattern pattern21 = Pattern.compile("<input\\s+.*\\s+value\\s*=\\s*[\"\'].*[\"\']\\s*>");
                Pattern pattern22 = Pattern.compile("<input\\s+.*\\s+placeholder\\s*=\\s*[\"\'].*[\"\']\\s*>");
                Pattern pattern23 = Pattern.compile("<form\\s+.*\\s+action\\s*=\\s*[\"\'].*[\"\']\\s*>");
                Pattern pattern24 = Pattern.compile("<form\\s+.*\\s+method\\s*=\\s*[\"\'].*[\"\']\\s*>");
                Pattern pattern25 = Pattern.compile("<textarea.*>.*</textarea>");

                boolean foundVulnerability = false;
                int lineNumber = 1;
                while ((line = bufferedReader.readLine()) != null) {
                    Matcher matcher1 = pattern1.matcher(line);
                    Matcher matcher2 = pattern2.matcher(line);
                    Matcher matcher3 = pattern3.matcher(line);
                    Matcher matcher4 = pattern4.matcher(line);
                    Matcher matcher5 = pattern5.matcher(line);
                    Matcher matcher6 = pattern6.matcher(line);
                    Matcher matcher7 = pattern7.matcher(line);
                    Matcher matcher8 = pattern8.matcher(line);
                    Matcher matcher9 = pattern9.matcher(line);
                    Matcher matcher10 = pattern10.matcher(line);
                    Matcher matcher11 = pattern11.matcher(line);
                    Matcher matcher12 = pattern12.matcher(line);
                    Matcher matcher13 = pattern13.matcher(line);
                    Matcher matcher14 = pattern14.matcher(line);
                    Matcher matcher15 = pattern15.matcher(line);
                    Matcher matcher16 = pattern16.matcher(line);
                    Matcher matcher17 = pattern17.matcher(line);
                    Matcher matcher18 = pattern18.matcher(line);
                    Matcher matcher19 = pattern19.matcher(line);
                    Matcher matcher20 = pattern20.matcher(line);
                    Matcher matcher21 = pattern21.matcher(line);
                    Matcher matcher22 = pattern22.matcher(line);
                    Matcher matcher23 = pattern23.matcher(line);
                    Matcher matcher24 = pattern24.matcher(line);
                    Matcher matcher25 = pattern25.matcher(line);
                    if (matcher1.find() || matcher2.find() || matcher3.find() || matcher4.find() || matcher5.find() || matcher6.find()
                            || matcher7.find() || matcher8.find() || matcher9.find() || matcher10.find() || matcher11.find()
                            || matcher12.find() || matcher13.find() || matcher14.find() || matcher15.find() || matcher16.find()
                            || matcher17.find() || matcher18.find() || matcher19.find() || matcher20.find() || matcher21.find()
                            || matcher22.find() || matcher23.find() || matcher24.find() || matcher25.find()) {
                        System.out.println("Possible XSS injection vulnerability found in line: "+lineNumber+" :" + line);
                        //Scanned="Possible SQL injection vulnerability found in line: " +lineNumber+" :"+ line;
                        numofVul++;

                        foundVulnerability = true;
                        // break;
                    }

                    lineNumber++;
                }
                if (!foundVulnerability) {
                    System.out.println("No XSS injection vulnerabilities found in this file.");
                }

                bufferedReader.close();
                fileReader.close();
            } catch (IOException e) {
                System.err.println("Error reading " + phpFile.getAbsolutePath() + ": " + e.getMessage());
            }
            System.out.println("---------------------------------------------------------------");
            System.out.println("---------------------------------------------------------------");
        }
        System.out.println("Total Numbers of XSS Vulnerabilities = " + numofVul);
        // return Scanned;
    }



//misssing Encryptionn of sensitive data


    static void missEncScanner(List<File> phpFiles)
    {
        String[] searchArray = {"openssl_encrypt" ,
                "openssl_decrypt" ,
                "mcrypt_encrypt" ,
                "mcrypt_decrypt",
                "base64_encode" ,
                "base64_decode" ,
                "sodium_crypto_secretbox" ,
                "password_hash" ,
                "password_verify" ,
                "openssl_pkcs7_encrypt" ,
                "openssl_pkcs7_decrypt" ,
                "openssl_random_pseudo_bytes" ,
                "hash"};
        boolean check=false;
        for (File phpFile : phpFiles) {
            try {
                int k=0;
                String [] used=new String[5];
                check=false;
                System.out.println("Searching for Functions " + " in " + phpFile.getAbsolutePath() + ":");
                FileReader fileReader = new FileReader(phpFile);
                BufferedReader bufferedReader = new BufferedReader(fileReader);
                String line;
                int lineNumber = 1;
                while ((line = bufferedReader.readLine()) != null) {
                    for (String searchItem : searchArray) {
                        if (line.contains(searchItem)) {
                            System.out.println("Found '" + searchItem + "' in line " + lineNumber + ": " + line);
                            used[k]=searchItem;
                            k++;
                            check=true;

                        }

                    }
                    lineNumber++;

                }
                if(check==true)
                {
                    /*System.out.println("the Functions that you are Missing are : ");

                    List<String> list1 = new ArrayList<>(Arrays.asList(searchArray));
                    List<String> list2 = new ArrayList<>(Arrays.asList(used));

                    list1.removeAll(list2);

                    String[] diff = list1.toArray(new String[0]);

                    System.out.print(Arrays.toString(diff));*/



                    System.out.println("Sensitive Data Are Encrypted in this File ");
                    System.out.println("--------------------------------------------------");
                    System.out.println("--------------------------------------------------");
                }

                if(check==false)
                {
                    System.out.println("No Functions are Found U R Vulnerable !");
                    List<String> list1 = new ArrayList<>(Arrays.asList(searchArray));
                    String[] funcs = list1.toArray(new String[0]);
                    System.out.println("Try to Add some of This Functions :- ");
                    System.out.print(Arrays.toString(funcs));
                    System.out.println("");
                    System.out.println("--------------------------------------------------");
                    System.out.println("--------------------------------------------------");
                }
                bufferedReader.close();
                fileReader.close();
            } catch (IOException e) {
                System.err.println("Error reading " + phpFile.getAbsolutePath() + ": " + e.getMessage());
            }
        }
    }





    static void FunM(List<File> phpFiles)
    {       String[] searchArray = {"mysqli_real_escape_string", "mysqli_prepare", "mysqli_stmt_bind_param","mysqli_stmt_execute","filter_input","htmlspecialchars","strip_tags","filter_var","htmlentities","urlencode"};
        boolean check=false;
        for (File phpFile : phpFiles) {
            try {
                int k=0;
                String [] used=new String[5];
                check=false;
                System.out.println("Searching for Functions " + " in " + phpFile.getAbsolutePath() + ":");
                FileReader fileReader = new FileReader(phpFile);
                BufferedReader bufferedReader = new BufferedReader(fileReader);
                String line;
                int lineNumber = 1;
                while ((line = bufferedReader.readLine()) != null) {
                    for (String searchItem : searchArray) {
                        if (line.contains(searchItem)) {
                            System.out.println("Found '" + searchItem + "' in line " + lineNumber + ": " + line);
                           used[k]=searchItem;
                           k++;
                            check=true;

                        }

                    }
                    lineNumber++;

                }
                if(check==true)
                {
                    System.out.println("the Functions that you are Missing are : ");

                    List<String> list1 = new ArrayList<>(Arrays.asList(searchArray));
                    List<String> list2 = new ArrayList<>(Arrays.asList(used));

                    list1.removeAll(list2);

                    String[] diff = list1.toArray(new String[0]);

                    System.out.print(Arrays.toString(diff));



                    System.out.println("");
                    System.out.println("--------------------------------------------------");
                    System.out.println("--------------------------------------------------");
                }

                if(check==false)
                {
                    System.out.println("No Functions are Found U R Vulnerable !");
                    List<String> list1 = new ArrayList<>(Arrays.asList(searchArray));
                    String[] funcs = list1.toArray(new String[0]);
                    System.out.println("Try to Add some of This Functions :- ");
                    System.out.print(Arrays.toString(funcs));
                    System.out.println("");
                    System.out.println("--------------------------------------------------");
                    System.out.println("--------------------------------------------------");
                }
                bufferedReader.close();
                fileReader.close();
            } catch (IOException e) {
                System.err.println("Error reading " + phpFile.getAbsolutePath() + ": " + e.getMessage());
            }
        }
    }

//                              C:\Users\LENOVO\Downloads\library-master

    public static void main(String[] args) {





        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter file path: ");
        String filePath = scanner.nextLine();

        File directory = new File(filePath);
        List<File> phpFiles = new ArrayList<File>();
        // Recursively search the directory and its subdirectories for PHP files
        for (File file : FileUtils.listFiles(directory, new String[]{"php"}, true)) {
            phpFiles.add(file);
        }

        System.out.println("Select a security case:");
        System.out.println("1. SQL injection Scanning");
        System.out.println("2. Cross-site scripting Scanning");
        System.out.println("3. Data Encryption Scanning");
        System.out.println("4. Functions used to mitigate Vulnerabilities");

        System.out.print("Enter your choice: ");
        int choice = scanner.nextInt();

        switch (choice) {
            case 1:
                sqlInjectionScanner(phpFiles);
                break;
            case 2:
                xssScanner(phpFiles);
                break;
            case 3:
                missEncScanner(phpFiles);
                break;
            case 4:
                FunM(phpFiles);
                break;
            default:
                System.out.println("Invalid choice.");
                break;
        }




        // Print the contents of each PHP file

    }
}
