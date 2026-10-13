import org.apache.ibatis.annotations.Update;
interface RenamedWriter {
    // ruleid: java-lab-idor-update-scope
    @Update("UPDATE lab_articles SET title=#{text} WHERE id=#{key} AND run_id=#{scope}")
    int write(long key, String scope, String text);
    // ruleid: java-lab-idor-update-scope
    @Update("update lab_articles set content=#{body} where id = #{article} and run_id = #{tenant}")
    int alternate(long article, String tenant, String body);
    // ok: java-lab-idor-update-scope
    @Update("UPDATE lab_articles SET title=#{text} WHERE id=#{key} AND run_id=#{scope} AND user_id=#{actor}")
    int owned(long key, String scope, long actor, String text);
    // ok: java-lab-idor-update-scope
    @Update("UPDATE other_table SET title=#{text} WHERE id=#{key} AND run_id=#{scope}")
    int outOfPolicy(long key, String scope, String text);
    // ok: java-lab-idor-update-scope
    @Update("UPDATE lab_articles SET title=#{text} WHERE id=#{key}")
    int outsideRunContract(long key, String text);
    // ruleid: java-lab-idor-update-scope
    @Update("UPDATE lab_articles SET user_id=#{actor}, title=#{text} WHERE id=#{key} AND run_id=#{scope}")
    int assignmentIsNotGuard(long key, String scope, long actor, String text);
    // ruleid: java-lab-idor-update-scope
    @Update("UPDATE lab_articles SET title=#{text} WHERE run_id=#{scope} AND id=#{key}")
    int reversed(long key, String scope, String text);
    // ok: java-lab-idor-update-scope
    @Update("UPDATE lab_articles SET title=#{text} WHERE user_id=#{actor} AND run_id=#{scope} AND id=#{key}")
    int reorderedOwner(long key, String scope, long actor, String text);
}
