package com.pi.ShodanClone;

import org.glassfish.jersey.server.ResourceConfig;
import org.springframework.stereotype.Component;

@Component
public class JerseyConfig extends ResourceConfig {
    public JerseyConfig() {
        register(HostWebService.class);
        register(CorsFilter.class);
        register(ApiKeyFilter.class);
        register(PreflightFilter.class);
    }
}