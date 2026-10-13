import java.util.Map;
import org.apache.ibatis.annotations.*;
import org.springframework.web.bind.annotation.RequestParam;

// Class names, mapper method names, map keys and tables differ from real SQLi.
class SearchEndpoint {
    Gateway gateway;
    Object search(@RequestParam String input) { return gateway.lookup(input); }
}
class Gateway {
    RenamedMapper mapper;
    Object lookup(String value) { return mapper.fetch(value); }
}
interface RenamedMapper {
    @SelectProvider(type = TextFactory.class, method = "build")
    Object fetch(@Param("needle") String value);
}
class TextFactory {
    public static String build(Map<String, Object> data) {
        return "SELECT id FROM alternate WHERE title='" + data.get("needle") + "'"; // SQLi positive
    }
}
class SafeEndpoint {
    SafeMapper mapper;
    Object search(@RequestParam String input) { return mapper.fetch(input); }
}
interface SafeMapper {
    @SelectProvider(type = BoundFactory.class, method = "build")
    Object fetch(@Param("needle") String value);
}
class BoundFactory {
    public static String build(Map<String, Object> data) {
        return "SELECT id FROM alternate WHERE title=#{needle}"; // negative: constant bound SQL
    }
}
class KeyEndpoint {
    KeyMapper mapper;
    Object search(@RequestParam String input) { return mapper.fetch(input); }
}
interface KeyMapper {
    @SelectProvider(type = OtherKeyFactory.class, method = "build")
    Object fetch(@Param("needle") String value);
}
class OtherKeyFactory {
    public static String build(Map<String, Object> data) {
        return "SELECT id FROM alternate WHERE title='" + data.get("unrelated") + "'"; // negative: key mismatch
    }
}
class UnselectedFactory {
    public static String build(Map<String, Object> data) {
        return "SELECT id FROM alternate WHERE title='" + data.get("needle") + "'"; // negative: no annotation edge
    }
}
interface Writer {
    @Update("UPDATE lab_articles SET title=#{text} WHERE id=#{key} AND run_id=#{scope}") // positive
    int unowned(long key, String scope, String text);
    @Update("update lab_articles set title=#{text} where id = #{key} and run_id = #{scope} and user_id = #{actor}") // negative
    int owned(long key, String scope, long actor, String text);
    @Update("UPDATE lab_articles SET user_id=#{actor},title=#{text} WHERE id=#{key} AND run_id=#{scope}") // positive: assignment not predicate
    int assignment(long key, String scope, long actor, String text);
    @Update("UPDATE other_table SET title=#{text} WHERE id=#{key} AND run_id=#{scope}") // outside policy
    int other(long key, String scope, String text);
}
record Article(long userId) {}
class Actor { long getId() { return 1; } }
class RenamedService {
    Writer writer;
    void missing(long key, String scope, Actor actor, Article original) {
        writer.unowned(key, scope, "text"); // service positive
    }
    void guarded(long key, String scope, Actor actor, Article original) {
        if (original.userId() != actor.getId()) { throw new SecurityException(); }
        writer.owned(key, scope, actor.getId(), "text"); // service negative
    }
    void logOnly(long key, String scope, Actor actor, Article original) {
        if (original.userId() != actor.getId()) { System.out.println("denied?"); }
        writer.owned(key, scope, actor.getId(), "text"); // service positive: no refusal
    }
    void tooLate(long key, String scope, Actor actor, Article original) {
        writer.owned(key, scope, actor.getId(), "text"); // service positive: check after write
        if (original.userId() != actor.getId()) { throw new SecurityException(); }
    }
    void wrongActor(long key, String scope, Actor actor, Actor other, Article original) {
        if (original.userId() != actor.getId()) { throw new SecurityException(); }
        writer.owned(key, scope, other.getId(), "text"); // service positive: wrong identity
    }
    void outOfPolicy(long key, String scope) {
        writer.other(key, scope, "text"); // negative: different table policy
    }
}
interface ReorderedWriter {
    @Update("UPDATE lab_articles SET title=#{text} WHERE run_id=#{scope} AND id=#{key}") // positive reordered conditions
    int write(long key, String scope, String text);
    @Update("UPDATE lab_articles SET title=#{text} WHERE user_id=#{actor} AND run_id=#{scope} AND id=#{key}") // negative
    int guarded(long key, String scope, long actor, String text);
}
