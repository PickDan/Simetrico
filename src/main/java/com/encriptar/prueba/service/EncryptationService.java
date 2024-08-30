package com.encriptar.prueba.service;

import javax.crypto.Cipher; //Operaciones de cifrado y descifrado.
import javax.crypto.SecretKeyFactory; //Generar claves secretas.
import javax.crypto.spec.PBEKeySpec; //Especifica la contraseña y otros parámetros para la generación de claves
import javax.crypto.spec.SecretKeySpec;//Especifica la clave de cifrado.
import java.security.SecureRandom;//Genera valores aleatorios seguros
import org.springframework.stereotype.Service;

@Service
public class EncryptationService {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final int KEY_LENGTH = 128;
    private static final int ITERATIONS = 10000;
    private static final int SALT_LENGTH = 16;


    // Deriva una clave AES de longitud fija a partir de la contraseña
    //Crea una clave para el cifrado
    private SecretKeySpec getKeySpec(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
        byte[] key = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, ALGORITHM);
    }

    // Genera un nuevo salt aleatorio(valor aleatorio seguro)
    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }
    //Método que sirve para cifrar con la contraseña y la llave segura
    public byte[] encrypt(byte[] data, String password) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        byte[] salt = generateSalt();
        SecretKeySpec keySpec = getKeySpec(password, salt);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedData = cipher.doFinal(data);
        // Devuelve el salt junto con los datos encriptados
        return concatenate(salt, encryptedData);
    }
    //Método para decifrar con los datos cifrados y la contraseña
    public byte[] decrypt(byte[] data, String password) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        byte[] salt = new byte[SALT_LENGTH];
        byte[] encryptedData = new byte[data.length - SALT_LENGTH];
        System.arraycopy(data, 0, salt, 0, SALT_LENGTH);
        System.arraycopy(data, SALT_LENGTH, encryptedData, 0, encryptedData.length);
        SecretKeySpec keySpec = getKeySpec(password, salt);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(encryptedData);
    }

    // Métodos para combinar salt y los datos cifrados en un mismo arreglo
    private byte[] concatenate(byte[] salt, byte[] data) {
        byte[] result = new byte[salt.length + data.length];
        System.arraycopy(salt, 0, result, 0, salt.length);
        System.arraycopy(data, 0, result, salt.length, data.length);
        return result;
    }
}
