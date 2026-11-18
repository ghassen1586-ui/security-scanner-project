package com.pi.ShodanClone;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface HostRepository extends MongoRepository<Host, String> {
}