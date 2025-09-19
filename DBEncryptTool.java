import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.sql.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

import javax.crypto.Cipher;

/**
 * DBEncryptTool
 *
 * - Connects to MySQL DB (config below)
 * - For each configured table/column, encrypts the column value using the keystore public key,
 *   wraps into WSO2-style JSON, base64-encodes that JSON, and updates the DB column.
 *
 * IMPORTANT: backup your DB before running.
 */
public class DBEncryptTool {

    private static String JDBC_URL;
    private static String DB_USER;
    private static String DB_PASS;
    private static String DB_DRIVER;

    private static String KEYSTORE_PATH;
    private static String KEYSTORE_PASS;
    private static String KEY_ALIAS;

    private static String ALGORITHM;

    private static List<String[]> TARGETS = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        System.out.println("DBEncryptTool starting...");

        // 1) Load config
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream("dbencrypttool.properties")) {
            props.load(fis);
        }

        JDBC_URL = props.getProperty("db.url");
        DB_USER = props.getProperty("db.user");
        DB_PASS = props.getProperty("db.password");
        DB_DRIVER = props.getProperty("db.driver");

        KEYSTORE_PATH = props.getProperty("keystore.path");
        KEYSTORE_PASS = props.getProperty("keystore.password");
        KEY_ALIAS = props.getProperty("keystore.alias");

        ALGORITHM = props.getProperty("encryption.algorithm");

        for (String entry : props.getProperty("targets").split(",")) {
            String[] parts = entry.trim().split("\\.");
            if (parts.length == 2) {
                TARGETS.add(new String[]{parts[0].trim(), parts[1].trim()});
            }
        }

        // 2) Load keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
            keyStore.load(fis, KEYSTORE_PASS.toCharArray());
        }
        Certificate cert = keyStore.getCertificate(KEY_ALIAS);
        if (cert == null) throw new IllegalStateException("Certificate not found: " + KEY_ALIAS);
        PublicKey publicKey = cert.getPublicKey();
        String thumbprint = sha1Hex(cert.getEncoded());

        System.out.println("Loaded keystore. Cert thumbprint (SHA-1): " + thumbprint);

        // 3) Connect DB
        Class.forName(DB_DRIVER);
        try (Connection conn = DriverManager.getConnection(JDBC_URL, DB_USER, DB_PASS)) {
            conn.setAutoCommit(false);

            for (String[] t : TARGETS) {
                processTableColumn(conn, t[0], t[1], publicKey, cert, thumbprint);
            }

            conn.commit();
        }

        System.out.println("DBEncryptTool finished.");
    }


    private static void processTableColumn(Connection conn, String table, String column,
                                           PublicKey publicKey, Certificate cert, String thumbprint) {
        System.out.printf("Processing %s.%s ...%n", table, column);

        // 1) Check that table and column exist
        try (ResultSet rsCols = conn.getMetaData().getColumns(null, null, table, column)) {
            if (!rsCols.next()) {
                System.out.printf("  Skipping: column %s not found in table %s%n", column, table);
                return;
            }
        } catch (SQLException e) {
            System.out.printf("  Error checking column %s in %s: %s%n", column, table, e.getMessage());
            return;
        }

        // 2) Figure out a primary key column to update by
        String pkColumn = guessPrimaryKey(conn, table);
        if (pkColumn == null) {
            System.out.printf("  Warning: could not find a primary key for table %s. Trying fallback update by matching column value.%n", table);
        } else {
            System.out.printf("  Using primary key column: %s%n", pkColumn);
        }

        // 3) Select rows
        String selectSql = pkColumn != null
                ? String.format("SELECT `%s`, `%s` FROM `%s`", pkColumn, column, table)
                : String.format("SELECT `%s` FROM `%s`", column, table);

        try (Statement sel = conn.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)) {
            ResultSet rs = sel.executeQuery(selectSql);

            // Prepare update SQL
            String updateSql;
            if (pkColumn != null) {
                updateSql = String.format("UPDATE `%s` SET `%s` = ? WHERE `%s` = ?", table, column, pkColumn);
            } else {
                // Fallback: update rows by matching the existing column value (be careful with duplicates)
                updateSql = String.format("UPDATE `%s` SET `%s` = ? WHERE `%s` = ?", table, column, column);
            }

            try (PreparedStatement upd = conn.prepareStatement(updateSql)) {
                int rowCount = 0;
                while (rs.next()) {
                    String pkValue = null;
                    String plainVal;
                    if (pkColumn != null) {
                        pkValue = rs.getString(1);
                        plainVal = rs.getString(2);
                    } else {
                        plainVal = rs.getString(1);
                    }

                    if (plainVal == null || plainVal.trim().isEmpty()) {
                        // nothing to encrypt
                        continue;
                    }

                    // If the value already looks like a base64-encoded JSON (our target), skip it.
                    if (looksLikeBase64Json(plainVal)) {
                        System.out.printf("  Skipping row (already looks encrypted): pk=%s%n", pkValue);
                        continue;
                    }

                    // Encrypt the plaintext to JSON and Base64-encode the JSON
                    String json = buildWso2JsonForPlaintext(plainVal, publicKey, cert, thumbprint);
                    String jsonBase64 = Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));

                    // Execute update
                    upd.setString(1, jsonBase64);
                    if (pkColumn != null) {
                        upd.setString(2, pkValue);
                    } else {
                        upd.setString(2, plainVal); // fallback WHERE old value = ?
                    }

                    int updated = upd.executeUpdate();
                    rowCount += updated;
                }
                System.out.printf("  Updated %d rows in %s.%s%n", rowCount, table, column);
            }
        } catch (SQLException ex) {
            System.out.printf("  SQL error while processing %s.%s : %s%n", table, column, ex.getMessage());
        } catch (Exception e) {
            System.out.printf("  Unexpected error while processing %s.%s : %s%n", table, column, e.getMessage());
        }
    }

    private static String buildWso2JsonForPlaintext(String plaintext, PublicKey publicKey,
                                                    Certificate cert, String thumbprint) throws Exception {
        // Encrypt plain using RSA/OAEP
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        String base64Cipher = Base64.getEncoder().encodeToString(cipherBytes);

        // Build JSON: {"c":"<base64>","t":"<algorithm>","tp":"<thumb>","tpd":"SHA-1"}
        String json = String.format("{\"c\":\"%s\",\"t\":\"%s\",\"tp\":\"%s\",\"tpd\":\"SHA-1\"}",
                base64Cipher, ALGORITHM, thumbprint);
        return json;
    }

    private static boolean looksLikeBase64Json(String value) {
        // crude heuristic: base64 string of JSON will often start with "eyJ" ({" in base64 -> eyJ)
        // or value may start with '{' if stored as JSON text. Also check if it decodes to JSON.
        String v = value.trim();
        if (v.startsWith("{")) return true;
        if (v.length() > 3 && (v.startsWith("eyJ") || v.startsWith("e3si"))) return true; // common base64 of JSON patterns
        return false;
    }

    private static String guessPrimaryKey(Connection conn, String table) {
        try (ResultSet pk = conn.getMetaData().getPrimaryKeys(null, null, table)) {
            if (pk.next()) {
                String pkCol = pk.getString("COLUMN_NAME");
                return pkCol;
            }
            // fallback heuristics
            // common PK names in WSO2 tables:
            String[] candidates = new String[] {"TOKEN_ID","CONSUMER_KEY","AUTH_CODE_KEY","ID","ID_","AUTH_REQ_ID", "ACCESS_TOKEN"};
            for (String cand : candidates) {
                try (ResultSet col = conn.getMetaData().getColumns(null, null, table, cand)) {
                    if (col.next()) return cand;
                }
            }
        } catch (SQLException e) {
            // ignore
        }
        return null;
    }

    private static String sha1Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] d = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
