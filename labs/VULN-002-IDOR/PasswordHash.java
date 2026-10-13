import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
class PasswordHash {
    public static void main(String[] args) throws Exception {
        String password = new BufferedReader(new InputStreamReader(System.in)).readLine();
        System.out.println(new BCryptPasswordEncoder(12).encode(password));
    }
}
