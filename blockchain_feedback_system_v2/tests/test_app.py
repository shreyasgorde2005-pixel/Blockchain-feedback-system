import json
import os
import tempfile
import unittest

import app as application
from werkzeug.security import generate_password_hash


class AppFlowTests(unittest.TestCase):
    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.old_database = application.DATABASE
        application.DATABASE = self.db_path
        application.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        application.init_db()
        with application.connect_db() as db:
            db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                       ("learner", generate_password_hash("correct horse battery"), "student", application.utc_now()))
            db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                       ("operator", generate_password_hash("correct horse battery"), "admin", application.utc_now()))
        self.client = application.app.test_client()

    def tearDown(self):
        application.DATABASE = self.old_database
        os.remove(self.db_path)

    def set_csrf(self, value="test-csrf"):
        with self.client.session_transaction() as session:
            session["csrf_token"] = value
        return value

    def test_student_submit_verify_and_privacy_display(self):
        token = self.set_csrf()
        response = self.client.post("/login", data={"csrf_token": token, "username": "learner",
                                  "password": "correct horse battery"})
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            token = session["csrf_token"]
        response = self.client.post("/student", data={"csrf_token": token, "category": "Teaching",
                                  "rating": "5", "comments": "Helpful course"})
        self.assertEqual(response.status_code, 302)
        with application.connect_db() as db:
            payload = json.loads(db.execute("SELECT data_json FROM blocks WHERE block_index=1").fetchone()[0])
        self.assertNotIn("user_id", payload)
        self.assertNotIn("username", payload)
        self.assertTrue(self.client.get("/verify").json["valid"])
        self.assertTrue(self.client.get("/verify/proof/1").json["valid"])
        with application.connect_db() as db:
            db.execute("UPDATE feedback SET comments='altered after submission' WHERE block_id = "
                       "(SELECT id FROM blocks WHERE block_index=1)")
        verification = self.client.get("/verify").json
        self.assertFalse(verification["valid"])
        self.assertIn("payload mismatch", verification["message"])

    def test_csrf_and_role_boundaries(self):
        self.assertEqual(self.client.post("/login", data={"username": "learner"}).status_code, 400)
        token = self.set_csrf()
        self.client.post("/login", data={"csrf_token": token, "username": "learner",
                         "password": "correct horse battery"})
        self.assertEqual(self.client.get("/admin/export.csv").status_code, 403)


if __name__ == "__main__":
    unittest.main()
