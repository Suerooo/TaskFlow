package model;

import org.mindrot.jbcrypt.BCrypt;

public class User {
    // Atributos estaticos
    private static int userCount = 0;

    // Atributos no estaticos
    private final int ID;
    private String username;
    private String email;
    private String hashPassword;

    public User(String username, String email, String password) {
        this.ID = ++userCount;
        setUsername(username);
        setEmail(email);
        setPassword(password);
    }

    public int getID() {
        return ID;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("El campo 'username' no puede ser nulo o vacío");
        }
        this.username = username.trim();
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new IllegalArgumentException("El campo 'email' no puede ser nulo o vacío");
        } else if (!email.matches("^[\\w.-]+@[\\w.-]+\\.[a-zA-Z]{2,}$")) {
            throw new IllegalArgumentException("Formato de 'email' mal intrducido");
        }
        this.email = email.trim();
    }

    public String getHashPassword() {
        return hashPassword;
    }

    public void setPassword(String password) {
        if (password == null || password.trim().isEmpty()) {
            throw new IllegalArgumentException("El campo 'password' no puede ser nulo o vacío");
        } else if (!password.matches("\\d{8}")) {
            throw new IllegalArgumentException("Minimo 8 carácteres");
        }

        this.hashPassword = BCrypt.hashpw(password, BCrypt.gensalt(6));
    }

}