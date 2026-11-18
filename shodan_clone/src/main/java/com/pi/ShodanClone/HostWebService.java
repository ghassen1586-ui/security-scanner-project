package com.pi.ShodanClone;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Component
@Path("/api")
public class HostWebService {

    @Autowired
    private HostRepository hostRepository;

    @GET
    @Path("/host/{ip}")
    @Produces(MediaType.APPLICATION_JSON)
    public Host getHostByIp(@PathParam("ip") String ip) {
        Optional<Host> host = hostRepository.findById(ip);
        return host.orElse(null);
    }

    @POST
    @Path("/host")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Host addHost(Host host) {
        return hostRepository.save(host);
    }

    @GET
    @Path("/hosts")
    @Produces(MediaType.APPLICATION_JSON)
    public List<Host> getAllHosts() {
        return hostRepository.findAll();
    }

    @PUT
    @Path("/host/{ip}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Host updateHost(Host host, @PathParam("ip") String ip) {
        host.setIp(ip);
        return hostRepository.save(host);
    }
}