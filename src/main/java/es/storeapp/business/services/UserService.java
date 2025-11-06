package es.storeapp.business.services;

import es.storeapp.business.entities.User;
import es.storeapp.business.exceptions.AuthenticationException;
import es.storeapp.business.exceptions.DuplicatedResourceException;
import es.storeapp.business.exceptions.InputValidationException;
import es.storeapp.business.exceptions.InstanceNotFoundException;
import es.storeapp.business.exceptions.ServiceException;
import es.storeapp.business.repositories.UserRepository;
import es.storeapp.business.utils.ExceptionGenerationUtils;
import es.storeapp.common.ConfigurationParameters;
import es.storeapp.common.Constants;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import jakarta.annotation.PostConstruct;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.mail.HtmlEmail;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private static final String SALT = "$2a$10$MN0gK0ldpCgN9jx6r0VYQO";

    @Autowired
    ConfigurationParameters configurationParameters;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MessageSource messageSource;

    @Autowired
    ExceptionGenerationUtils exceptionGenerationUtils;

    private File resourcesDir;

    @PostConstruct
    public void init() {
        resourcesDir = new File(configurationParameters.getResources());
    }

    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Transactional(readOnly = true)
    public User login(String email, String clearPassword) throws AuthenticationException {
        if (!userRepository.existsUser(email)) {
            throw exceptionGenerationUtils.toAuthenticationException(Constants.AUTH_INVALID_USER_MESSAGE, email);
        }
        User user = userRepository.findByEmailAndPassword(email, BCrypt.hashpw(clearPassword, SALT));
        if (user == null) {
            throw exceptionGenerationUtils.toAuthenticationException(Constants.AUTH_INVALID_PASSWORD_MESSAGE, email);
        }
        return user;
    }

    @Transactional()
    public void sendResetPasswordEmail(String email, String url, Locale locale)
            throws AuthenticationException, ServiceException {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw exceptionGenerationUtils.toAuthenticationException(Constants.AUTH_INVALID_USER_MESSAGE, email);
        }
        String token = UUID.randomUUID().toString();

        try {

            System.setProperty("mail.smtp.ssl.protocols", "TLSv1.2");

            HtmlEmail htmlEmail = new HtmlEmail();
            htmlEmail.setHostName(configurationParameters.getMailHost());
            htmlEmail.setSmtpPort(configurationParameters.getMailPort());
            htmlEmail.setSslSmtpPort(Integer.toString(configurationParameters.getMailPort()));
            htmlEmail.setAuthentication(configurationParameters.getMailUserName(),
                    configurationParameters.getMailPassword());
            htmlEmail.setSSLOnConnect(configurationParameters.getMailSslEnable() != null
                    && configurationParameters.getMailSslEnable());
            if (configurationParameters.getMailStartTlsEnable()) {
                htmlEmail.setStartTLSEnabled(true);
                htmlEmail.setStartTLSRequired(true);
            }
            htmlEmail.addTo(email, user.getName());
            htmlEmail.setFrom(configurationParameters.getMailFrom());
            htmlEmail.setSubject(messageSource.getMessage(Constants.MAIL_SUBJECT_MESSAGE,
                    new Object[]{user.getName()}, locale));

            String link = url + Constants.PARAMS
                    + Constants.TOKEN_PARAM + Constants.PARAM_VALUE + token + Constants.NEW_PARAM_VALUE
                    + Constants.EMAIL_PARAM + Constants.PARAM_VALUE + email;

            htmlEmail.setHtmlMsg(messageSource.getMessage(Constants.MAIL_TEMPLATE_MESSAGE,
                    new Object[]{user.getName(), link}, locale));

            htmlEmail.setTextMsg(messageSource.getMessage(Constants.MAIL_HTML_NOT_SUPPORTED_MESSAGE,
                    new Object[0], locale));

            htmlEmail.send();
        } catch (Exception ex) {
            logger.error(ex.getMessage(), ex);
            throw new ServiceException(ex.getMessage());
        }

        user.setResetPasswordToken(token);
        userRepository.update(user);
    }

    @Transactional
    public User create(String name, String email, String password, String address,
            String image, byte[] imageContents) throws DuplicatedResourceException {
        if (userRepository.findByEmail(email) != null) {
            throw exceptionGenerationUtils.toDuplicatedResourceException(Constants.EMAIL_FIELD, email,
                    Constants.DUPLICATED_INSTANCE_MESSAGE);
        }
        User user = userRepository.create(new User(name, email, BCrypt.hashpw(password, SALT), address, image));
        saveProfileImage(user.getUserId(), image, imageContents);
        return user;
    }

    @Transactional
    public User update(Long id, String name, String email, String address, String image, byte[] imageContents)
            throws DuplicatedResourceException, InstanceNotFoundException, ServiceException {
        User user = userRepository.findById(id);
        User emailUser = userRepository.findByEmail(email);
        if (emailUser != null && !Objects.equals(emailUser.getUserId(), user.getUserId())) {
            throw exceptionGenerationUtils.toDuplicatedResourceException(Constants.EMAIL_FIELD, email,
                    Constants.DUPLICATED_INSTANCE_MESSAGE);
        }
        user.setName(name);
        user.setEmail(email);
        user.setAddress(address);
        if (image != null && image.trim().length() > 0 && imageContents != null) {
            try {
                deleteProfileImage(id, user.getImage());
            } catch (Exception ex) {
                logger.error(ex.getMessage(), ex);
            }
            saveProfileImage(id, image, imageContents);
            user.setImage(image);
        }
        return userRepository.update(user);
    }

    @Transactional
    public User changePassword(Long id, String oldPassword, String password)
            throws InstanceNotFoundException, AuthenticationException {
        User user = userRepository.findById(id);
        if (user == null) {
            throw exceptionGenerationUtils.toAuthenticationException(
                    Constants.AUTH_INVALID_USER_MESSAGE, id.toString());
        }
        if (userRepository.findByEmailAndPassword(user.getEmail(), BCrypt.hashpw(oldPassword, SALT)) == null) {
            throw exceptionGenerationUtils.toAuthenticationException(Constants.AUTH_INVALID_PASSWORD_MESSAGE,
                    id.toString());
        }
        user.setPassword(BCrypt.hashpw(password, SALT));
        return userRepository.update(user);
    }

    @Transactional
    public User changePassword(String email, String password, String token) throws AuthenticationException {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw exceptionGenerationUtils.toAuthenticationException(Constants.AUTH_INVALID_USER_MESSAGE, email);
        }
        if (user.getResetPasswordToken() == null || !user.getResetPasswordToken().equals(token)) {
            throw exceptionGenerationUtils.toAuthenticationException(Constants.AUTH_INVALID_TOKEN_MESSAGE, email);
        }
        user.setPassword(BCrypt.hashpw(password, SALT));
        user.setResetPasswordToken(null);
        return userRepository.update(user);
    }

    @Transactional
    public User removeImage(Long id) throws InstanceNotFoundException, ServiceException {
        User user = userRepository.findById(id);
        try {
            deleteProfileImage(id, user.getImage());
        } catch (IOException ex) {
            logger.error(ex.getMessage(), ex);
            throw new ServiceException(ex.getMessage());
        }
        user.setImage(null);
        return userRepository.update(user);
    }

    @Transactional
    public byte[] getImage(Long id) throws InstanceNotFoundException {
        User user = userRepository.findById(id);
        try {
            return getProfileImage(id, user.getImage());
        } catch (IOException ex) {
            logger.error(ex.getMessage(), ex);
            return null;
        }
    }

    private void saveProfileImage(Long id, String image, byte[] imageContents) {
        if (image != null && image.trim().length() > 0 && imageContents != null) {
            // Additional server-side validation
            try {
                validateImageBytes(image, imageContents);
            } catch (InputValidationException e) {
                logger.error("Invalid image file detected: {}", e.getMessage());
                return; // Do not save invalid files
            }
            
            File userDir = new File(resourcesDir, id.toString());
            userDir.mkdirs();
            File profilePicture = new File(userDir, image);
            try (FileOutputStream outputStream = new FileOutputStream(profilePicture);) {
                IOUtils.copy(new ByteArrayInputStream(imageContents), outputStream);
            } catch (Exception e) {
                logger.error(e.getMessage(), e);
            }
        }
    }

    private void deleteProfileImage(Long id, String image) throws IOException {
        if (image != null && image.trim().length() > 0) {
            File userDir = new File(resourcesDir, id.toString());
            File profilePicture = new File(userDir, image);
            Files.delete(profilePicture.toPath());
        }
    }

    private byte[] getProfileImage(Long id, String image) throws IOException {
        if (image != null && image.trim().length() > 0) {
            File userDir = new File(resourcesDir, id.toString());
            File profilePicture = new File(userDir, image);
            try (FileInputStream input = new FileInputStream(profilePicture)) {
                return IOUtils.toByteArray(input);
            }
        }
        return null;
    }
    
    private void validateImageBytes(String filename, byte[] imageContents) throws InputValidationException {
        if (imageContents == null || imageContents.length == 0) {
            throw new InputValidationException("Empty file");
        }
        
        // Validate file extension
        String extension = "";
        int lastDotIndex = filename.lastIndexOf('.');
        if (lastDotIndex > 0) {
            extension = filename.substring(lastDotIndex + 1).toLowerCase();
        }
        
        if (!extension.matches("jpg|jpeg|png|gif|bmp|webp")) {
            throw new InputValidationException("Invalid file extension");
        }
        
        // Validate magic bytes
        if (!isValidImageBytes(imageContents)) {
            throw new InputValidationException("Invalid image file signature");
        }
    }
    
    private boolean isValidImageBytes(byte[] bytes) {
        if (bytes.length < 8) {
            return false;
        }
        
        // JPEG
        if (bytes.length >= 3 && (bytes[0] & 0xFF) == 0xFF && (bytes[1] & 0xFF) == 0xD8 && (bytes[2] & 0xFF) == 0xFF) {
            return true;
        }
        
        // PNG
        if (bytes.length >= 8 && (bytes[0] & 0xFF) == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && 
            bytes[3] == 0x47 && (bytes[4] & 0xFF) == 0x0D && (bytes[5] & 0xFF) == 0x0A && 
            (bytes[6] & 0xFF) == 0x1A && (bytes[7] & 0xFF) == 0x0A) {
            return true;
        }
        
        // GIF
        if (bytes.length >= 6 && bytes[0] == 0x47 && bytes[1] == 0x49 && bytes[2] == 0x46 && 
            bytes[3] == 0x38 && (bytes[4] == 0x37 || bytes[4] == 0x39) && bytes[5] == 0x61) {
            return true;
        }
        
        // BMP
        if (bytes.length >= 2 && bytes[0] == 0x42 && bytes[1] == 0x4D) {
            return true;
        }
        
        // WebP
        if (bytes.length >= 12 && bytes[0] == 0x52 && bytes[1] == 0x49 && bytes[2] == 0x46 && 
            bytes[3] == 0x46 && bytes[8] == 0x57 && bytes[9] == 0x45 && bytes[10] == 0x42 && bytes[11] == 0x50) {
            return true;
        }
        
        return false;
    }

}
