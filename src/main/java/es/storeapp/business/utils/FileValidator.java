package es.storeapp.business.utils;

import es.storeapp.business.exceptions.InputValidationException;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
public class FileValidator {

    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList("jpg", "jpeg", "png", "gif", "bmp", "webp");
    private static final List<String> ALLOWED_MIME_TYPES = Arrays.asList(
        "image/jpeg",
        "image/jpg", 
        "image/png",
        "image/gif",
        "image/bmp",
        "image/webp"
    );
    
    private static final long MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

    public void validateImageFile(MultipartFile file) throws InputValidationException {
        if (file == null || file.isEmpty()) {
            return; // No file provided is valid (optional field)
        }

        // Validate file size
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new InputValidationException("File size exceeds maximum allowed size of 5MB");
        }

        // Validate file extension
        String originalFilename = file.getOriginalFilename();
        if (originalFilename == null || originalFilename.trim().isEmpty()) {
            throw new InputValidationException("Invalid file name");
        }

        String extension = getFileExtension(originalFilename);
        if (!ALLOWED_EXTENSIONS.contains(extension.toLowerCase())) {
            throw new InputValidationException("Invalid file extension. Allowed: jpg, jpeg, png, gif, bmp, webp");
        }

        // Validate MIME type
        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_MIME_TYPES.contains(contentType.toLowerCase())) {
            throw new InputValidationException("Invalid file type. Only image files are allowed");
        }

        // Validate magic bytes (file signature)
        try {
            byte[] fileBytes = file.getBytes();
            if (!isValidImageFile(fileBytes)) {
                throw new InputValidationException("File content does not match a valid image format");
            }
        } catch (IOException e) {
            throw new InputValidationException("Error reading file content");
        }
    }

    private String getFileExtension(String filename) {
        int lastDotIndex = filename.lastIndexOf('.');
        if (lastDotIndex == -1 || lastDotIndex == filename.length() - 1) {
            return "";
        }
        return filename.substring(lastDotIndex + 1);
    }

    private boolean isValidImageFile(byte[] fileBytes) {
        if (fileBytes == null || fileBytes.length < 8) {
            return false;
        }

        // Check magic bytes for common image formats
        return isJpeg(fileBytes) || isPng(fileBytes) || isGif(fileBytes) || 
               isBmp(fileBytes) || isWebp(fileBytes);
    }

    private boolean isJpeg(byte[] bytes) {
        return bytes.length >= 3 &&
               (bytes[0] & 0xFF) == 0xFF &&
               (bytes[1] & 0xFF) == 0xD8 &&
               (bytes[2] & 0xFF) == 0xFF;
    }

    private boolean isPng(byte[] bytes) {
        return bytes.length >= 8 &&
               (bytes[0] & 0xFF) == 0x89 &&
               bytes[1] == 0x50 &&
               bytes[2] == 0x4E &&
               bytes[3] == 0x47 &&
               (bytes[4] & 0xFF) == 0x0D &&
               (bytes[5] & 0xFF) == 0x0A &&
               (bytes[6] & 0xFF) == 0x1A &&
               (bytes[7] & 0xFF) == 0x0A;
    }

    private boolean isGif(byte[] bytes) {
        return bytes.length >= 6 &&
               bytes[0] == 0x47 &&
               bytes[1] == 0x49 &&
               bytes[2] == 0x46 &&
               bytes[3] == 0x38 &&
               (bytes[4] == 0x37 || bytes[4] == 0x39) &&
               bytes[5] == 0x61;
    }

    private boolean isBmp(byte[] bytes) {
        return bytes.length >= 2 &&
               bytes[0] == 0x42 &&
               bytes[1] == 0x4D;
    }

    private boolean isWebp(byte[] bytes) {
        return bytes.length >= 12 &&
               bytes[0] == 0x52 &&
               bytes[1] == 0x49 &&
               bytes[2] == 0x46 &&
               bytes[3] == 0x46 &&
               bytes[8] == 0x57 &&
               bytes[9] == 0x45 &&
               bytes[10] == 0x42 &&
               bytes[11] == 0x50;
    }
}
