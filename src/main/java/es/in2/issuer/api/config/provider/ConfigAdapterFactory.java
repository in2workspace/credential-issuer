package es.in2.issuer.api.config.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class ConfigAdapterFactory {
    List<GenericConfigAdapter> configAdapters;

    public ConfigAdapterFactory(List<GenericConfigAdapter> configServices) {
        this.configAdapters = configServices;
    }

    public GenericConfigAdapter getAdapter() {
        //check if list is empty or size is greater than 1
        if (configAdapters.isEmpty() || configAdapters.size() > 1) {
            throw new RuntimeException("Invalid number of config services found");
        }

        return configAdapters.get(0);
    }
}