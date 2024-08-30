package com.encriptar.prueba.controller;

import com.encriptar.prueba.service.EncryptationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class EncryptationController {

    @Autowired
    private EncryptationService encryptationService;

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @PostMapping("/encrypt")
    public ResponseEntity<byte[]> encryptFile(@RequestParam("file") MultipartFile file,
                                              @RequestParam("password") String password) {
        try {
            byte[] encryptedData = encryptationService.encrypt(file.getBytes(), password);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=encrypted_" + file.getOriginalFilename())
                    .body(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error al encriptar el archivo: " + e.getMessage()).getBytes());
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<byte[]> decryptFile(@RequestParam("file") MultipartFile file,
                                              @RequestParam("password") String password) {
        try {
            byte[] decryptedData = encryptationService.decrypt(file.getBytes(), password);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + file.getOriginalFilename().replace("encrypted_", ""))
                    .body(decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Error al desencriptar el archivo: " + e.getMessage()).getBytes());
        }
    }
}
