import com.opencsv.CSVReader;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.lang.System.err;
import static java.lang.System.out;

public class Main {
  public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
    if (args.length != 2) {
      err.println("Usage: <password database file.txt> <password file to check.csv>");
      err.println(
          " - Download the password file here: https://haveibeenpwned.com/Passwords - *USE THE 'ordered by hash' version*.");
      err.println(" - Be nice and use the torrent download if possible.");
      err.println(" - Password file to check can be a CSV export from keepass for example.");
      err.println(
          " - Alternatively a list of passwords. In this case make sure to add 'password' as the first line of the file.");
      System.exit(1);
    }
    MessageDigest sha1 = MessageDigest.getInstance("SHA1");
    RandomAccessFile r = new RandomAccessFile(args[0], "r");
    long length = r.length();
    long numpasses = length / 44;
    out.printf("Number of passwords: ~%d\n", numpasses);
    try (BufferedReader in = new BufferedReader(new FileReader(args[1]));
        CSVReader csv = new CSVReader(in)) {
      List<String> headers = Arrays.asList(csv.readNext());
      int password =
          headers.stream()
              .map(String::toLowerCase)
              .collect(Collectors.toList())
              .indexOf("password");
      String[] line;
      while ((line = csv.readNext()) != null) {
        byte[] digest = sha1.digest(line[password].getBytes(StandardCharsets.UTF_8));
        char[] hashChars = new char[40];
        for (int i = 0; i < 20; i++) {
          hashChars[i * 2] = toHex((byte) ((digest[i] >>> 4) & 0xf));
          hashChars[i * 2 + 1] = toHex((byte) (digest[i] & 0xf));
        }
        String hashedPass = new String(hashChars);
        long a = 0;
        long b = length - 41;
        byte[] buf = new byte[41];
        while (a <= b) {
          long m = (a + b) / 2;
          do {
            r.seek(m);
            r.readFully(buf);
            for (int i = 40; i >= 0 && buf[i] != ':'; i--) {
              m--;
            }
          } while (buf[40] != ':');
          String aM = new String(buf, 0, 40, StandardCharsets.ISO_8859_1);
          int compare = aM.compareTo(hashedPass);
          if (compare < 0) {
            int code;
            while ((code = r.read()) != -1 && code != ':') m++;
            a = m + 1;
          } else if (compare > 0) {
            b = m - 42;
          } else {
            String[] toPrint = line;
            out.printf(
                "PWNED for %s\n",
                IntStream.range(0, toPrint.length)
                    .mapToObj(
                        i -> {
                          if (i == password) return null;
                          else return toPrint[i];
                        })
                    .filter(Main::isNotBlank)
                    .collect(Collectors.joining(", ")));
            break;
          }
        }
      }
    }
  }

  private static boolean isNotBlank(String s) {
    return s != null && s.trim().length() > 0;
  }

  public static char toHex(byte nibble) {
    if (nibble > 9) return (char) ('A' + nibble - 10);
    return (char) ('0' + nibble);
  }
}
