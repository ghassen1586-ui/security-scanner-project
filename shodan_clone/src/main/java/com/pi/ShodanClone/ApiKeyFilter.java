package com.pi.ShodanClone;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Provider
public class ApiKeyFilter implements ContainerRequestFilter {

    private static final List<String> VALID_API_KEYS = Arrays.asList("secu-demo-key-2026");

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if ("OPTIONS".equalsIgnoreCase(requestContext.getMethod())) {
            return;
        }

        String key = requestContext.getHeaderString("X-API-Key");
        if (key == null || !VALID_API_KEYS.contains(key)) {
            requestContext.abortWith(
                Response.status(Response.Status.UNAUTHORIZED)
                        .entity("{\"error\":\"Missing or invalid API key\"}")
                        .type("application/json")
                        .build()
            );
        }
    }
}