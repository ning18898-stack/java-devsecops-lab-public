import json
from .models import TRANSITIONS
from .safety import error, sanitize, preview
from labscan.core import now


def history(db, fid, action, note, old=None, new=None):
    db.execute("INSERT INTO finding_history(finding_id,action,from_status,to_status,note,timestamp) VALUES (?,?,?,?,?,?)",
               (fid, action, old, new, sanitize(note), now()))


def get_finding(db, fid, active=False):
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if row is None:
        error(404, "发现项不存在")
    if active and row["merged_into"]:
        error(409, "该管理项已关联至其他管理项")
    return dict(row)


class Service:
    def __init__(self, database):
        self.database = database

    def runs(self, page, page_size):
        with self.database.connect() as db:
            total = db.execute("SELECT count(*) FROM scan_runs").fetchone()[0]
            rows = db.execute("SELECT id FROM scan_runs ORDER BY timestamp DESC,id LIMIT ? OFFSET ?",
                              (page_size, (page - 1) * page_size)).fetchall()
        return {"total": total, "items": [self.run(row[0]) for row in rows], "page": page, "page_size": page_size}

    def run(self, run_id):
        with self.database.connect() as db:
            row = db.execute("SELECT id,source_revision,source_fingerprint,timestamp,status,steps,tool_versions,imported_at,report_sha256 "
                             "FROM scan_runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                error(404, "扫描运行不存在")
            result = dict(row)
            result["steps"] = json.loads(result["steps"])
            result["tool_versions"] = json.loads(result["tool_versions"])
            result["evidence"] = [dict(r) for r in db.execute("SELECT id,path,sha256,availability FROM evidence WHERE run_id=?", (run_id,))]
            result["observation_count"] = db.execute("SELECT count(*) FROM observations WHERE run_id=?", (run_id,)).fetchone()[0]
            result["finding_ids"] = [r[0] for r in db.execute("SELECT DISTINCT k.finding_id FROM finding_keys k JOIN observations o "
                                                            "ON k.fingerprint=o.fingerprint WHERE o.run_id=?", (run_id,))]
            result["independent_vulnerability_count"] = None
            return sanitize(result)

    def findings(self, tool, severity, status, query, sort, order, page, page_size):
        clauses = ["f.merged_into IS NULL"]
        values = []
        for name, value in (("severity", severity), ("status", status)):
            if value:
                clauses.append(f"f.{name}=?")
                values.append(value)
        if tool:
            clauses.append("EXISTS(SELECT 1 FROM finding_keys k WHERE k.finding_id=f.id AND k.tool=?)")
            values.append(tool)
        if query:
            clauses.append("instr(lower(f.title),lower(?))>0")
            values.append(query)
        where = " AND ".join(clauses)
        # sort/order are validated Literals at the API boundary.
        column = {"created_at": "f.created_at", "updated_at": "f.updated_at", "severity":
                  "CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'informational' THEN 1 ELSE 0 END"}[sort]
        with self.database.connect() as db:
            total = db.execute("SELECT count(*) FROM findings f WHERE " + where, values).fetchone()[0]
            rows = db.execute("SELECT f.* FROM findings f WHERE " + where + f" ORDER BY {column} {order},f.id {order} LIMIT ? OFFSET ?",
                              (*values, page_size, (page - 1) * page_size)).fetchall()
            items = []
            for row in rows:
                item = dict(row)
                item["tools"] = [r[0] for r in db.execute("SELECT DISTINCT tool FROM finding_keys WHERE finding_id=?", (row["id"],))]
                item["observation_count"] = db.execute("SELECT count(*) FROM observations o JOIN finding_keys k ON o.fingerprint=k.fingerprint WHERE k.finding_id=?", (row["id"],)).fetchone()[0]
                items.append(item)
            return {"total": total, "items": sanitize(items), "page": page, "page_size": page_size}

    def detail(self, fid):
        with self.database.connect() as db:
            result = get_finding(db, fid)
            result["allowed_transitions"] = TRANSITIONS[result["status"]] if not result["merged_into"] else []
            observations = []
            for row in db.execute("SELECT o.* FROM observations o JOIN finding_keys k ON o.fingerprint=k.fingerprint WHERE k.finding_id=? ORDER BY o.id", (fid,)):
                item = json.loads(row["raw_json"])
                item.update({"id": row["id"], "source_snippet": row["source_snippet"],
                             "evidence": [dict(e) for e in db.execute("SELECT e.id,e.path,e.sha256,e.availability FROM evidence e JOIN observation_evidence oe ON e.id=oe.evidence_id WHERE oe.observation_id=?", (row["id"],))]})
                observations.append(item)
            result["observations"] = observations
            for table, key in (("finding_history", "history"), ("repairs", "repairs"), ("verifications", "verifications")):
                result[key] = [dict(r) for r in db.execute(f"SELECT * FROM {table} WHERE finding_id=? ORDER BY id", (fid,))]
            for v in result["verifications"]:
                v["evidence_ids"] = json.loads(v["evidence_ids"])
            result["associated_from"] = [r[0] for r in db.execute("SELECT id FROM findings WHERE merged_into=?", (fid,))]
            return sanitize(result)

    def stats(self):
        with self.database.connect() as db:
            return {"runs": db.execute("SELECT count(*) FROM scan_runs").fetchone()[0],
                    "observations": db.execute("SELECT count(*) FROM observations").fetchone()[0],
                    "managed_findings": db.execute("SELECT count(*) FROM findings WHERE merged_into IS NULL").fetchone()[0],
                    "independent_vulnerability_count": None,
                    "risk": {r[0] or "unknown": r[1] for r in db.execute("SELECT severity,count(*) FROM findings WHERE merged_into IS NULL GROUP BY severity")},
                    "statuses": {r[0]: r[1] for r in db.execute("SELECT status,count(*) FROM findings WHERE merged_into IS NULL GROUP BY status")},
                    "recent_runs": self.runs(1, 5)["items"]}

    def status(self, fid, body):
        with self.database.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = get_finding(db, fid, True)
            target = body.status.value
            if row["version"] != body.version:
                error(409, "记录已变更，请刷新后操作")
            if target not in TRANSITIONS[row["status"]]:
                error(409, "不允许此状态转换")
            if target == "pending_verification" and not db.execute("SELECT 1 FROM repairs WHERE finding_id=?", (fid,)).fetchone():
                error(409, "进入待复测必须先登记修复声明")
            if target == "closed":
                v = db.execute("SELECT v.* FROM verifications v JOIN scan_runs r ON r.id=v.run_id WHERE v.id=? AND v.finding_id=? AND v.conclusion='remediated' AND r.status='COMPLETED'",
                               (body.verification_id, fid)).fetchone()
                latest = db.execute("SELECT max(id) FROM verifications WHERE finding_id=?", (fid,)).fetchone()[0]
                last_pending = db.execute("SELECT max(timestamp) FROM finding_history WHERE finding_id=? AND to_status='pending_verification'", (fid,)).fetchone()[0]
                if not v or v["id"] != latest or v["timestamp"] <= last_pending:
                    error(409, "关闭必须引用本轮最新、有证据的修复复测结论")
            db.execute("UPDATE findings SET status=?,version=version+1,updated_at=? WHERE id=?", (target, now(), fid))
            note = body.note + (f" [verification_id={body.verification_id}]" if target == "closed" else "")
            history(db, fid, "status", note, row["status"], target)
        return self.detail(fid)

    def note(self, fid, body):
        with self.database.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            get_finding(db, fid, True)
            history(db, fid, "note", body.note)
        return self.detail(fid)

    def repair(self, fid, body):
        with self.database.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = get_finding(db, fid, True)
            if row["status"] != "fixing":
                error(409, "只允许在修复中登记修复声明")
            cursor = db.execute("INSERT INTO repairs(finding_id,reference,note,timestamp) VALUES (?,?,?,?)",
                                (fid, sanitize(body.reference), sanitize(body.note), now()))
            history(db, fid, "repair", f"修复声明 #{cursor.lastrowid}：{body.note}")
        return self.detail(fid)

    def verify(self, fid, body):
        with self.database.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = get_finding(db, fid, True)
            if row["status"] != "pending_verification":
                error(409, "只允许在待复测登记复测记录")
            repair = db.execute("SELECT * FROM repairs WHERE id=? AND finding_id=?", (body.repair_id, fid)).fetchone()
            run = db.execute("SELECT * FROM scan_runs WHERE id=?", (body.run_id,)).fetchone()
            if not repair or not run:
                error(422, "修复或扫描关联无效")
            if body.conclusion == "remediated":
                if run["status"] != "COMPLETED" or run["timestamp"] <= repair["timestamp"]:
                    error(409, "修复结论需要修复声明之后完成的真实运行")
                if db.execute("SELECT 1 FROM observations o JOIN finding_keys k ON o.fingerprint=k.fingerprint WHERE k.finding_id=? AND o.run_id=?", (fid, body.run_id)).fetchone():
                    error(409, "该运行仍报告本管理项，不能宣称已修复")
            for eid in set(body.evidence_ids):
                evidence = db.execute("SELECT * FROM evidence WHERE id=? AND run_id=? AND availability='available'", (eid, body.run_id)).fetchone()
                if not evidence or evidence["content"] is None:
                    error(422, "复测证据必须属于所选运行且实际可用")
            cursor = db.execute("INSERT INTO verifications(finding_id,repair_id,run_id,evidence_ids,conclusion,scope,note,timestamp) VALUES (?,?,?,?,?,?,?,?)",
                                (fid, body.repair_id, body.run_id, json.dumps(sorted(set(body.evidence_ids))),
                                 body.conclusion, sanitize(body.scope), sanitize(body.note), now()))
            history(db, fid, "verification", f"复测 #{cursor.lastrowid} ({body.conclusion})：{body.note}")
        return self.detail(fid)

    def associate(self, fid, body):
        with self.database.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            source = get_finding(db, fid, True)
            target = get_finding(db, body.target_id, True)
            if fid == body.target_id or source["version"] != body.version:
                error(409, "关联自身或过期记录无效")
            if source["status"] != "unreviewed" or target["status"] not in ("unreviewed", "confirmed"):
                error(409, "关联仅允许尚未处置的来源项与待研判/已确认目标")
            if db.execute("SELECT 1 FROM repairs WHERE finding_id=? UNION SELECT 1 FROM verifications WHERE finding_id=?", (fid, fid)).fetchone():
                error(409, "已有修复/复测的管理项不能关联")
            db.execute("UPDATE finding_keys SET finding_id=? WHERE finding_id=?", (body.target_id, fid))
            db.execute("UPDATE findings SET merged_into=?,version=version+1,updated_at=? WHERE id=?", (body.target_id, now(), fid))
            # Retain the strongest reported severity when grouping observations.
            ranking = {None: 0, "informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
            severity = max((source["severity"], target["severity"]), key=ranking.get)
            db.execute("UPDATE findings SET severity=?,version=version+1,updated_at=? WHERE id=?", (severity, now(), body.target_id))
            note = f"人工确认管理项 #{fid} 关联至 #{body.target_id}：{body.note}"
            history(db, fid, "associate", note)
            history(db, body.target_id, "associate", note)
        return self.detail(body.target_id)

    def evidence(self, eid):
        with self.database.connect() as db:
            row = db.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
            if not row:
                error(404, "证据不存在")
            path = row["path"]
            # Operational/container logs may contain environment secrets; don't expose them.
            allowed = path in ("semgrep-vulnerable.json", "semgrep-secure.json", "codeql-vulnerable.sarif", "codeql-secure.sarif", "zap.json", "zap-execution.json")
            if not allowed:
                error(403, "该证据仅保留引用，不提供内容预览")
            if row["content"] is None:
                error(404, "原始证据缺失，未提供内容")
            text, truncated = preview(row["content"])
            return {"id": eid, "run_id": row["run_id"], "path": path, "sha256": row["sha256"],
                    "content": text, "truncated": truncated, "redacted": True}
