package dev.nikalolo.securejavaapi;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

// The web layer with the real security rules: without @Import the slice
// would not load SecurityConfig and these tests would see no security at all.
@WebMvcTest(HealthController.class)
@Import(SecurityConfig.class)
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void healthIsAllowedWithHeaders() throws Exception {
        expectSecurityHeaders(mockMvc.perform(get("/health")).andExpect(status().isOk()));
    }

    @Test
    void postToHealthIsDenied() throws Exception {
        expectSecurityHeaders(mockMvc.perform(post("/health")).andExpect(status().isForbidden()));
    }

    @Test
    void unknownPathIsDenied() throws Exception {
        expectSecurityHeaders(mockMvc.perform(get("/does-not-exist")).andExpect(status().isForbidden()));
    }

    @Test
    void errorPathIsDenied() throws Exception {
        expectSecurityHeaders(mockMvc.perform(get("/error")).andExpect(status().isForbidden()));
    }

    private void expectSecurityHeaders(ResultActions result) throws Exception {
        result.andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(header().string("Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'"));
    }
}
