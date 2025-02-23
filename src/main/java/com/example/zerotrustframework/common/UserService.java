package com.example.zerotrustframework.common;

public interface UserService {

    public User LoadUserByUsername(String username);

    public boolean AddUser(User user);

    public boolean LogUser(String username, String Password);

    public boolean DeleteUser(String Username);

    public boolean UpdateUser(User user);
}
