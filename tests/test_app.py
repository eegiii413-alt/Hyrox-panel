import re
import unittest
from types import SimpleNamespace

import bcrypt

import app as dashboard_app


class FakeQuery:
    def __init__(self, table_name: str, client: "FakeSupabase") -> None:
        self.table_name = table_name
        self.client = client
        self.filters: list[tuple[str, object]] = []
        self.changes: dict[str, object] | None = None
        self.new_row: dict[str, object] | None = None
        self.deleting = False

    def insert(self, row: dict[str, object]) -> "FakeQuery":
        self.client.operations.append((self.table_name, "insert", row))
        self.new_row = row
        return self

    def delete(self) -> "FakeQuery":
        self.client.operations.append((self.table_name, "delete"))
        self.deleting = True
        return self

    def select(self, columns: str) -> "FakeQuery":
        self.client.operations.append((self.table_name, "select", columns))
        return self

    def update(self, changes: dict[str, object]) -> "FakeQuery":
        self.client.operations.append((self.table_name, "update", changes))
        self.changes = changes
        return self

    def eq(self, column: str, value: object) -> "FakeQuery":
        self.client.operations.append((self.table_name, "eq", column, value))
        self.filters.append((column, value))
        return self

    def limit(self, count: int) -> "FakeQuery":
        self.client.operations.append((self.table_name, "limit", count))
        return self

    def order(self, column: str, desc: bool = False) -> "FakeQuery":
        self.client.operations.append((self.table_name, "order", column, desc))
        return self

    def execute(self) -> SimpleNamespace:
        table = self.client.rows.setdefault(self.table_name, [])
        if self.new_row is not None:
            row = {"id": max((r["id"] for r in table), default=0) + 1, **self.new_row}
            table.append(row)
            return SimpleNamespace(data=[row])
        if self.deleting:
            removed = [r for r in table if all(r.get(c) == v for c, v in self.filters)]
            self.client.rows[self.table_name] = [r for r in table if r not in removed]
            return SimpleNamespace(data=removed)
        rows = [
            row
            for row in self.client.rows.get(self.table_name, [])
            if all(row.get(column) == value for column, value in self.filters)
        ]
        if self.changes is not None:
            for row in rows:
                row.update(self.changes)
        return SimpleNamespace(data=rows)


class FakeSupabase:
    def __init__(self) -> None:
        self.operations: list[tuple[object, ...]] = []
        self.rows: dict[str, list[dict[str, object]]] = {
            "users": [
                {
                    "id": 1,
                    "email": "eegii_413@yahoo.com",
                    "password_hash": bcrypt.hashpw(
                        b"TestPassword!", bcrypt.gensalt()
                    ).decode("utf-8"),
                }
            ],
            "content_drafts": [
                {
                    "id": 1,
                    "title": "HYROX зөвлөгөө",
                    "content": "Бэлтгэлээ төлөвлөөрэй.",
                    "status": "draft",
                    "created_at": "2026-11-12T10:00:00+00:00",
                }
            ],
            "bookings": [
                {
                    "id": 1,
                    "customer_name": "Бат",
                    "email": "bat@example.com",
                    "booking_date": "2026-11-15",
                    "session_name": "HYROX анхан шат",
                    "status": "confirmed",
                    "created_at": "2026-11-12T10:00:00+00:00",
                }
            ],
        }

    def table(self, table_name: str) -> FakeQuery:
        return FakeQuery(table_name, self)


class DashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_supabase = dashboard_app.supabase
        self.fake_supabase = FakeSupabase()
        dashboard_app.supabase = self.fake_supabase
        dashboard_app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = dashboard_app.app.test_client()

    def tearDown(self) -> None:
        dashboard_app.supabase = self.original_supabase

    def csrf_token(self) -> str:
        response = self.client.get("/login")
        match = re.search(
            rb'name="csrf_token" value="([^"]+)"',
            response.data,
        )
        if match is None:
            self.fail("Login form did not include a CSRF token.")
        return match.group(1).decode("utf-8")

    def test_login_and_list_drafts(self) -> None:
        response = self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token(),
                "email": "EEGII_413@YAHOO.COM",
                "password": "TestPassword!",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/dashboard")

        dashboard = self.client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("HYROX зөвлөгөө".encode(), dashboard.data)
        self.assertIn("Батлах".encode(), dashboard.data)
        self.assertIn("Татгалзах".encode(), dashboard.data)

    def change_status(self, action: str, draft_id: int = 1):
        token = self.csrf_token()
        self.log_in()
        return self.client.post(
            f"/drafts/{draft_id}/status",
            data={"csrf_token": token, "action": action},
            follow_redirects=True,
        )

    def test_approve_draft(self) -> None:
        response = self.change_status("approve")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.fake_supabase.rows["content_drafts"][0]["status"], "approved")
        self.assertIn("Ноорог батлагдлаа.".encode(), response.data)
        self.assertIn("Батлагдсан".encode(), response.data)
        self.assertNotIn(b'value="approve"', response.data)

    def test_reject_draft(self) -> None:
        response = self.change_status("reject")
        self.assertEqual(self.fake_supabase.rows["content_drafts"][0]["status"], "rejected")
        self.assertIn("Татгалзсан".encode(), response.data)

    def test_already_decided_draft_is_not_changed(self) -> None:
        self.fake_supabase.rows["content_drafts"][0]["status"] = "approved"
        response = self.change_status("reject")
        self.assertEqual(self.fake_supabase.rows["content_drafts"][0]["status"], "approved")
        self.assertIn("аль хэдийн шийдвэрлэгдсэн".encode(), response.data)

    def test_unknown_action_is_ignored(self) -> None:
        self.change_status("delete")
        self.assertEqual(self.fake_supabase.rows["content_drafts"][0]["status"], "draft")

    def test_status_change_requires_csrf(self) -> None:
        self.log_in()
        self.client.post("/drafts/1/status", data={"action": "approve"})
        self.assertEqual(self.fake_supabase.rows["content_drafts"][0]["status"], "draft")

    def test_wrong_password_is_rejected(self) -> None:
        response = self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token(),
                "email": "eegii_413@yahoo.com",
                "password": "incorrect",
            },
        )
        self.assertEqual(response.status_code, 401)
        with self.client.session_transaction() as user_session:
            self.assertNotIn("user_id", user_session)

    def log_in(self) -> None:
        with self.client.session_transaction() as user_session:
            user_session["user_id"] = 1
            user_session["email"] = "eegii_413@yahoo.com"

    def test_bookings_table(self) -> None:
        self.log_in()
        response = self.client.get("/bookings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<table", response.data)
        self.assertIn("Бат".encode(), response.data)
        self.assertIn("Баталгаажсан".encode(), response.data)

    def test_sidebar_and_coming_soon_pages(self) -> None:
        self.log_in()
        for path in ("/facebook", "/chat"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertIn("Удахгүй".encode(), response.data)
            for label in ("Контент", "Facebook", "Чат", "Захиалга"):
                self.assertIn(label.encode(), response.data)

    def test_new_pages_require_login(self) -> None:
        for path in ("/bookings", "/facebook", "/chat"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.location, "/login")

    def tour_form(self, **overrides: str) -> dict[str, str]:
        with self.client.session_transaction() as user_session:
            user_session["_csrf_token"] = "tok"
        data = {
            "csrf_token": "tok",
            "name": "Тэрэлж аялал",
            "destination": "Тэрэлж",
            "start_date": "2026-12-20",
            "days": "2",
            "price": "250000",
            "seats": "10",
        }
        data.update(overrides)
        return data

    def test_tour_add_edit_search_delete(self) -> None:
        self.log_in()
        tours = self.fake_supabase.rows.setdefault("tours", [])

        response = self.client.post("/tours/new", data=self.tour_form(), follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(tours), 1)
        self.assertEqual(tours[0]["days"], 2)
        self.assertIn("Шинэ аялал нэмэгдлээ.".encode(), response.data)
        self.assertIn("250,000₮".encode(), response.data)

        response = self.client.post(
            "/tours/1/edit", data=self.tour_form(name="Тэрэлж гүйлт", price="300000"), follow_redirects=True
        )
        self.assertEqual(self.fake_supabase.rows["tours"][0]["name"], "Тэрэлж гүйлт")
        self.assertEqual(self.fake_supabase.rows["tours"][0]["price"], 300000)
        self.assertIn("Өөрчлөлт хадгалагдлаа.".encode(), response.data)

        found = self.client.get("/tours?q=гүйлт")
        self.assertIn("Тэрэлж гүйлт".encode(), found.data)
        missing = self.client.get("/tours?q=Хөвсгөл")
        self.assertIn("Илэрц олдсонгүй".encode(), missing.data)

        confirm = self.client.get("/tours/1/delete")
        self.assertIn("Тийм, устгах".encode(), confirm.data)
        self.assertEqual(len(self.fake_supabase.rows["tours"]), 1)

        response = self.client.post("/tours/1/delete", data={"csrf_token": "tok"}, follow_redirects=True)
        self.assertEqual(self.fake_supabase.rows["tours"], [])
        self.assertIn("Аялал устгагдлаа.".encode(), response.data)

    def test_tour_form_validation(self) -> None:
        self.log_in()
        response = self.client.post("/tours/new", data=self.tour_form(name="", price="abc"))
        self.assertEqual(response.status_code, 400)
        self.assertIn("«Аяллын нэр» талбарыг бөглөнө үү.".encode(), response.data)
        self.assertIn("бүхэл тоо".encode(), response.data)
        self.assertEqual(self.fake_supabase.rows.get("tours", []), [])

    def test_delete_requires_csrf(self) -> None:
        self.log_in()
        self.fake_supabase.rows["staff"] = [
            {"id": 1, "full_name": "Мөнхзул", "position": "Дасгалжуулагч", "phone": None, "email": None}
        ]
        self.client.post("/staff/1/delete", data={})
        self.assertEqual(len(self.fake_supabase.rows["staff"]), 1)
        page = self.client.get("/staff")
        self.assertIn("Мөнхзул".encode(), page.data)
        self.assertIn("Ажилчдын".encode(), page.data)

    def test_crud_pages_require_login(self) -> None:
        for path in ("/tours", "/tours/new", "/tours/1/edit", "/tours/1/delete", "/staff", "/staff/new"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 302, path)

    def test_dashboard_requires_login(self) -> None:
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/login")


if __name__ == "__main__":
    unittest.main()
