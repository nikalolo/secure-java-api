package canary;

import java.security.MessageDigest;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// scan canary, not compiled: must trigger unrestricted-request-mapping (r/ rule)
// and use-of-md5 (p/java; also in p/owasp-top-ten, so it can't prove p/java alone)
@RestController
class UnmappedMethod {

    @RequestMapping("/canary")
    String canary() {
        return "canary";
    }

    byte[] weakHash(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }
}
