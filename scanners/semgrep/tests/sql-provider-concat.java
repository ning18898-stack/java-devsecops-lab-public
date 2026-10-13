import java.util.Map;
class RenamedProvider {
    String fromMap(Map<String, Object> args) {
        // ruleid: java-sql-provider-concat
        return "SELECT id FROM lab_articles WHERE title='" + args.get("needle") + "'";
    }
    String direct(String input) {
        // ruleid: java-sql-provider-concat
        return "select id from other_table where name='" + input;
    }
    String update(String value) {
        // ruleid: java-sql-provider-concat
        return "UPDATE other_table SET title='" + value;
    }
    String bound() {
        // ok: java-sql-provider-concat
        return "SELECT id FROM lab_articles WHERE title=#{needle}";
    }
    String constants() {
        // ok: java-sql-provider-concat
        return "SELECT id FROM lab_articles " + "WHERE id=1";
    }
    String message(String input) {
        // ok: java-sql-provider-concat
        return "Hello " + input;
    }
    String builder(String input) {
        // ok: java-sql-provider-concat
        return new StringBuilder("SELECT id FROM lab_articles WHERE title='").append(input).toString();
    }
}
