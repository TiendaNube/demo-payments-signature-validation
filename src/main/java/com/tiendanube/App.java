package com.tiendanube;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class App {
    public static void main(String[] args) {
        String data = "https://api.mercadopago.com/alpha/platforms/tienda-nube/payment/ticket|1681495199419|4c76452899cb5741308f0b3c08b63fa7034a1308df4df43475d0613a402ad48e";
        String signature = "O1CYMwBNCd1npNQjzRskF78dQ8uw0JIUM2d2Dz+zYee5dG0B0bldnFgSG/RnVkGLOFeBcnm1H1vLWhFenQRO4N9IpWkytATQ7k4uZHktC7cyhZPqHkQBvMYtL33l2nmb5uVZrdJ+hGHJdU82Do7Gc4JDutM/vXAWT+J8swe502Sz83qavhodZH+SwclrXfEnumDYmV4SeGMm/yl4d2t7pvGdKhJG/9EtJH6W9EZp9NI46V3V05/UuRgUfk+hgab+wIW3wtXWtrFywIqkiFxS3n5IrG0S5SCokqxxJ7IdcDB4J/xZJI+zeS5gY+7zjs5xBtdjKdl2p23rDnqbG8culwh6Xres3qIvjK3lRbS39DtC4AYkRHpFMNHTZnlrwnJ1U5kwBGbSTTbz/bx3k1jHNsgRm7zJzsOzVBVd5oIssnOHYIKs4q61u9L0/Kbj3DPLj6h00wNGeCIzb9UxM+S/IIqp1SxN+WItY7GkwnXM3WYiJL+1W4ZDLfVcbwy6OU4ElZVDv9PKfaCuHJKCZOpCuDYUq1RrO5GB7/UrUKJ35oawo+BFx2PMvXAbeSbWsk7zBMfw8PTNR33QK1oZY0JnQM5JRe4dhPgKF/+BJR8peSp8BnNykQAJfR/L9SYxE8uOHqFa8HF0zs73peSkiPGismWv2Tp8710ZqSbuHgOkDNs=";
        PublicKey publicKey;

        try {
            publicKey = RSASigner.loadKey("src/main/resources/tiendanube_public.der");
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        try {
            System.out.println("Verification result: " + RSASigner.verify(data, signature, publicKey));
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private static class RSASigner {
        public static String digest(String data) throws NoSuchAlgorithmException {
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(dataBytes);
            return Base64.getEncoder().encodeToString(hashBytes);
        }

        public static boolean verify(String data, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
            byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initVerify(publicKey);
            signer.update(dataBytes);
            return signer.verify(signatureBytes);
        }

        public static PublicKey loadKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
        }
    }
}
