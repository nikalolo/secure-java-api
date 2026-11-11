package dev.nikalolo.securejavaapi;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

// Loads only the web layer (controllers, MVC config), not the whole app.
@WebMvcTest(HealthController.class)
class HealthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void healthReturnsUp() throws Exception {
        mockMvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value("UP"));
    }

    // Only GET is mapped. A security-minded test: verify the endpoint
    // doesn't silently accept other methods.
    @Test
    void healthRejectsPost() throws Exception {
        mockMvc.perform(post("/health"))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    void unknownPathReturns404() throws Exception {
        mockMvc.perform(get("/does-not-exist"))
                .andExpect(status().isNotFound());
    }
}
