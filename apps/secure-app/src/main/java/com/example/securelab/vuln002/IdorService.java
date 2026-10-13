package com.example.securelab.vuln002;
public final class IdorService {
    private final IdorDatabase database;
    public IdorService(IdorDatabase database) { this.database=database; }
    public IdorArticle find(long id,IdorPrincipal principal) {
        try(var session=database.openTransaction()) {
            return require(session.getMapper(IdorMapper.class).find(id,principal.getRunId()));
        }
    }
    public IdorArticle update(long id,IdorPrincipal principal,IdorRequest request) {
        try(var session=database.openTransaction()) {
            var mapper=session.getMapper(IdorMapper.class);
            var original=require(mapper.find(id,principal.getRunId()));
            if(original.userId()!=principal.getId()) { throw new IdorFailure(403); }
            int changed=mapper.update(id,principal.getRunId(),principal.getId(),request.title(),request.content());
            if(changed==0) {
                // Preserve correct idempotent PUT behavior with MySQL affected-row settings.
                var current=require(mapper.find(id,principal.getRunId()));
                if(current.userId()!=principal.getId()) { throw new IdorFailure(403); }
                if(!current.title().equals(request.title()) || !current.content().equals(request.content())) {
                    throw new IdorFailure(404);
                }
            }
            var result=require(mapper.find(id,principal.getRunId()));
            session.commit();
            return result;
        }
    }
    private IdorArticle require(IdorArticle article) {
        if(article==null) { throw new IdorFailure(404); }
        return article;
    }
}
