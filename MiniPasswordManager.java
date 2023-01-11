import java.util.*;
import java.io.*;
import java.security.*;
public class MiniPasswordManager {
     /** userMap is a Hashtable keyed by username, and has 
      HashedPasswordTuples as its values */
     private static Hashtable dUserMap;

     /** location of the password file on disk */
     private static String dPwdFile;

     /** chooses a salt for the user, computes the salted hash 
      of the user's password, and adds a new entry into the
      userMap hashtable for the user. */
     public static void add(String username, String password) throws Exception {
          int salt = chooseNewSalt();
          HashedPasswordTuple ur = new HashedPasswordTuple(getSaltedHash(password, salt), salt);
          dUserMap.put(username,ur);
     }


     /** computes a new, random 12-bit salt */
     public static int chooseNewSalt() throws NoSuchAlgorithmException {
          return getSecureRandom((int)Math.pow(2,12));
     }

     /** returns a cryptographically random number in the range [0,max) */
     private static int getSecureRandom(int max) throws NoSuchAlgorithmException {
          SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
          return Math.abs(sr.nextInt());
     }

     /** returns a salted, SHA hash of the password */
     public static String getSaltedHash(String pwd, int salt) throws Exception {
          return computeSHA(pwd + "|" + salt);
     }

     /** returns the SHA-256 hash of the provided preimage as a String */
     private static String computeSHA(String preimage) throws Exception {
          MessageDigest md = null;
          md = MessageDigest.getInstance("SHA-256");
          md.update(preimage.getBytes("UTF-8"));
          byte raw[] = md.digest();
          return new String (Base64.getEncoder().encode(raw));
     }

     /** returns true iff the username and password are in the database */
     public static boolean checkPassword(String username, String password) {
          try {
               HashedPasswordTuple t = (HashedPasswordTuple)dUserMap.get(username);

               return (t == null) ? false : t.getHashedPassword().equals(getSaltedHash(password, t.getSalt()));
               
          } catch (Exception e) {
          }
          return false;
     }

     /** Password file management operations follow **/
     public static void init(String pwdFile) throws Exception {
          dUserMap = HashedSaltedPasswordFile.load(pwdFile);
          dPwdFile = pwdFile;
     }

     /** forces a write of the password file to disk */
     public static void flush() throws Exception {
          HashedSaltedPasswordFile.store (dPwdFile, dUserMap);
     }

     /** adds a new username/password combination to the database, or
      replaces an existing one. */
     public static void main(String argv[]) {
          String pwdFile = null;
          String userName = null;
          Scanner sc = new Scanner(System.in);
          try {
               System.out.println("Enter your password file path: ");
               pwdFile = sc.nextLine();
               System.out.println("Enter your username: ");
               userName = sc.nextLine();
               init(pwdFile);
               String password, onlyLetters, onlyLower;
               do
               {
                    System.out.print("Enter new password for " + userName + ": ");
                    BufferedReader br =
                            new BufferedReader(new InputStreamReader(System.in));
                    password = br.readLine();
                    onlyLetters = password.replaceAll("\\P{L}", "");
                    onlyLower = onlyLetters.replaceAll("[^a-z]","");

                    if (password.length() < 10 || onlyLetters.length() == password.length()|| onlyLetters.length() == onlyLower.length())
                         System.out.print("Password must be at least 10 characters long and include at least one uppercase letter and at least one number or Special Characer \n");
                    //if password does not meet requirements, requirements are outputed to user
               }while(password.length() < 10 || onlyLetters.length() == password.length()|| onlyLetters.length() == onlyLower.length());//this will loop until password meets requirements
               add(userName, password);
               flush();
          } catch (Exception e) {
               if ((pwdFile != null) && (userName != null)) {
                    System.err.println("Error: Could not read or write " + pwdFile);
               } else {
                    System.err.println("Usage: java " +
                            "com.learnsecurity.MiniPasswordManager" +
                            " <pwdfile> <username>");
               }
          }
     }
}

/** This class is a simple container that stores a salt, and a 
 salted, hashed passsord.  */
class HashedPasswordTuple {
     private String dHpwd;
     private int dSalt;
     public HashedPasswordTuple(String p, int s) {
          dHpwd = p; dSalt = s;
     }

     /** Constructs a HashedPasswordTuple pair from a line in
      the password file. */
     public HashedPasswordTuple(String line) throws Exception {
          StringTokenizer st =
                  new StringTokenizer(line, HashedSaltedPasswordFile.DELIMITER_STR);
          dHpwd = st.nextToken(); // hashed + salted password 
          dSalt = Integer.parseInt(st.nextToken()); // salt 
     }

     public String getHashedPassword() {
          return dHpwd;
     }

     public int getSalt() {
          return dSalt;
     }

     /** returns a HashedPasswordTuple in string format so that it
      can be written to the password file. */
     public String toString () {
          return (dHpwd + HashedSaltedPasswordFile.DELIMITER_STR + (""+dSalt));
     }
}

/** This class extends a HashedPasswordFile to support salted, hashed passwords. */
class HashedSaltedPasswordFile extends HashedPasswordFile {

     /* The load method overrides its parent.FN"s, as a salt also needs to be
        read from each line in the password file. */
     public static Hashtable load(String pwdFile) {
          Hashtable userMap = new Hashtable();
          try {
               FileReader fr = new FileReader(pwdFile);
               BufferedReader br = new BufferedReader(fr);
               String line;
               while ((line = br.readLine()) != null) {
                    int delim = line.indexOf(DELIMITER_STR);
                    String username=line.substring(0,delim);
                    HashedPasswordTuple ur =
                            new HashedPasswordTuple(line.substring(delim+1));
                    userMap.put(username, ur);
               }
          } catch (Exception e) {
               System.err.println ("Warning: Could not load password file.");
          }
          return userMap;
     }
}

/** This class supports a password file that stores hashed (but not salted)
 passwords. */
class HashedPasswordFile {

     /* the delimiter used to separate fields in the password file */
     public static final char DELIMITER = ':';
     public static final String DELIMITER_STR = "" + DELIMITER;

     /* We assume that DELIMITER does not appear in username and other fields. */
     public static Hashtable load(String pwdFile) {
          Hashtable userMap = new Hashtable();
          try {
               FileReader fr = new FileReader(pwdFile);
               BufferedReader br = new BufferedReader(fr);
               String line;
               while ((line = br.readLine()) != null) {
                    int delim = line.indexOf(DELIMITER_STR);
                    String username = line.substring(0,delim);
                    String hpwd = line.substring(delim+1);
                    userMap.put(username, hpwd);
               }
          } catch (Exception e) {
               System.err.println ("Warning: Could not load password file.");
          }
          return userMap;
     }

     public static void store(String pwdFile, Hashtable userMap) throws Exception {
          try {
               FileWriter fw = new FileWriter(pwdFile);
               Enumeration e = userMap.keys();
               while (e.hasMoreElements()) {
                    String uname = (String)e.nextElement();
                    fw.write(uname + DELIMITER_STR +
                            userMap.get(uname).toString() + "\n");
               }
               fw.close();
          } catch (Exception e) {
               e.printStackTrace();
          }
     }
}
