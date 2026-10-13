package com.example.securelab.vuln001;

import java.util.List;

public final class LabService {
    private final LabDatabase database;

    public LabService(LabDatabase database) { this.database = database; }

    public List<LabArticle> search(String query) { return database.search(query); }
}
