package com.pi.ShodanClone;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import java.util.List;

@Document(collection = "hosts")
public class Host {

    @Id
    private String ip;
    private List<Integer> openPorts;
    private List<String> banners;

    public Host() {}

    public Host(String ip, List<Integer> openPorts, List<String> banners) {
        this.ip = ip;
        this.openPorts = openPorts;
        this.banners = banners;
    }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public List<Integer> getOpenPorts() { return openPorts; }
    public void setOpenPorts(List<Integer> openPorts) { this.openPorts = openPorts; }

    public List<String> getBanners() { return banners; }
    public void setBanners(List<String> banners) { this.banners = banners; }
}